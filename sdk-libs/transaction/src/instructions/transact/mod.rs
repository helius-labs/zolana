//! Client-side transact assembly in two layers. The low level is
//! [`SppProofInputs`] (the assembled transaction sent to the prover), written
//! as a struct literal with explicitly encoded output slots; it serves custom
//! UTXOs (ring/swap flows). The high level is
//! [`ConfidentialTransaction`], which validates input order at construction,
//! derives the change outputs and pads both inputs and outputs to a declared or
//! automatically selected [`Shape`], then encrypts the result into [`SppProofInputs`].
//! [`PrivateTxHash`] produces the `private_tx_hash` shared as a public input by
//! the SPP and ring proofs.

mod encryption;
pub mod external_data;
mod inputs;
mod outputs;
mod ring;
mod settlement;
pub mod shape;
pub mod transaction;

use solana_address::Address;
use zolana_interface::MAX_INPUT_TREES;
use zolana_keypair::{shielded::ShieldedAddress, viewing_key::random_blinding};

pub use crate::indexer_types::{OutputContext, OutputSlot, ShieldedTransaction};
pub use crate::utxo::SppProofOutputUtxo;
pub use encryption::ResolvedOwnerTag;
pub use external_data::{ExternalData, SettlementTransfer};
pub use inputs::{pad_input_utxos, validate_input_tree_order};
pub use outputs::Recipient;
pub use ring::inputs_require_p256;
pub use settlement::{
    asset_field, signed_magnitude_to_field, PublicTransferRequest, PublicTransfers,
    SettlementTarget, BN254_MODULUS_DEC,
};
pub use shape::{
    auto_shapes, canonical_shape, resolve_shape, Shape, SPP_CONSOLIDATION_SHAPE,
    SPP_SUPPORTED_SHAPES,
};
pub use transaction::{PrivateTxHash, SppProofInputs};

use ring::sender_owner_tag;

use crate::{error::TransactionError, utxo::SppProofInputUtxo, Mint, WalletUtxo, SOL_MINT};

/// Build a confidential transaction from ordered input UTXOs.
///
/// Typical flows:
/// - Transfer: [`new`](Self::new) → [`transfer`](Self::transfer) → [`encrypt`](Self::encrypt).
/// - Deposit: [`new`](Self::new) → [`deposit`](Self::deposit) → [`encrypt`](Self::encrypt).
/// - Withdraw: [`new`](Self::new) → [`withdraw`](Self::withdraw) → [`encrypt`](Self::encrypt).
///
/// For SOL, use [`transfer_sol`](Self::transfer_sol), [`deposit_sol`](Self::deposit_sol)
/// or [`withdraw_sol`](Self::withdraw_sol). Multiple operations can be combined
/// before encryption.
///
///
/// Transfer to another shielded address:
/// ```ignore
/// let mut tx = ConfidentialTransaction::new(inputs, payer)?;
/// tx.transfer(&recipient, mint.asset, amount)?;
/// let proof_inputs = tx.encrypt(&keys)?;
/// ```
///
/// Deposit from a public SPL token account:
/// ```ignore
/// let mut tx = ConfidentialTransaction::new(inputs, payer)?;
/// tx.deposit(mint, amount, source_token_account)?;
/// let proof_inputs = tx.encrypt(&keys)?;
/// ```
///
/// Withdraw to a public SPL token account:
/// ```ignore
/// let mut tx = ConfidentialTransaction::new(inputs, payer)?;
/// tx.withdraw(mint.asset, amount, destination_token_account)?;
/// let proof_inputs = tx.encrypt(&keys)?;
/// ```
#[derive(Clone)]
pub struct ConfidentialTransaction {
    inputs: Vec<WalletUtxo>,
    outputs: Vec<SppProofOutputUtxo>,
    public_transfers: Vec<PublicTransferRequest>,
    payer: Address,
    blinding_seed: [u8; 32],
    output_tree_id: u16,
    first_nullifier: [u8; 32],
    input_tree_ids: Vec<u16>,
    ring_program_id: Option<Address>,
    padded_inputs: Option<Vec<SppProofInputUtxo>>,
}

impl ConfidentialTransaction {
    pub fn inputs(&self) -> &[WalletUtxo] {
        &self.inputs
    }

    pub fn payer(&self) -> Address {
        self.payer
    }

    pub fn blinding_seed(&self) -> &[u8; 32] {
        &self.blinding_seed
    }

    pub fn first_nullifier(&self) -> &[u8; 32] {
        &self.first_nullifier
    }

    pub fn input_tree_ids(&self) -> &[u16] {
        &self.input_tree_ids
    }

    /// Create a transaction from wallet UTXOs in the caller's order.
    ///
    /// Steps:
    /// 1. Require a real input in the first slot.
    /// 2. Verify real inputs and require padding to use their trees.
    /// 3. Require each tree to occupy one contiguous run, including padding.
    /// 4. Read the first nullifier and initialize the transaction with a fresh
    ///    blinding seed and no outputs or public transfers.
    pub fn new(inputs: Vec<WalletUtxo>, payer: Address) -> Result<Self, TransactionError> {
        // 1. Require a real input in the first slot.
        if inputs
            .first()
            .ok_or(TransactionError::NoInputs)?
            .utxo
            .owner
            .is_zero()
        {
            return Err(TransactionError::DummyInFirstInputSlot);
        }

        // 2. Verify real inputs and collect their tree IDs.
        let mut input_tree_ids: Vec<u16> = Vec::with_capacity(1);
        for (index, input) in inputs.iter().enumerate() {
            if input.utxo.owner.is_zero() {
                continue;
            }
            if input.utxo.data.utxo_data().is_some() && input.data_hash.is_none() {
                return Err(TransactionError::MissingInputDataHash { index });
            }
            if input.utxo.data.ring_data().is_some() && input.ring_data_hash.is_none() {
                return Err(TransactionError::MissingInputRingDataHash { index });
            }
            if input.utxo.hash(
                &input.nullifier_pubkey,
                &input.data_hash.unwrap_or_default(),
                &input.ring_data_hash.unwrap_or_default(),
                input.tree_id,
            )? != input.utxo_hash
            {
                return Err(TransactionError::InputCommitmentMismatch { index });
            }
            if !input_tree_ids.contains(&input.tree_id) {
                input_tree_ids.push(input.tree_id);
            }
        }
        if input_tree_ids.is_empty() {
            return Err(TransactionError::NoInputs);
        }
        if input_tree_ids.len() > MAX_INPUT_TREES {
            return Err(TransactionError::TooManyInputTrees {
                got: input_tree_ids.len(),
                max: MAX_INPUT_TREES,
            });
        }
        for (index, input) in inputs.iter().enumerate() {
            if input.utxo.owner.is_zero() && !input_tree_ids.contains(&input.tree_id) {
                return Err(TransactionError::PaddingInUndeclaredTree {
                    index,
                    tree_id: input.tree_id,
                });
            }
        }

        // 3. Require one contiguous run per tree, preserving the input order.
        let mut seen = Vec::new();
        for (index, input) in inputs.iter().enumerate() {
            let tree_id = input.tree_id;
            if seen.last() == Some(&tree_id) {
                continue;
            }
            if seen.contains(&tree_id) {
                return Err(TransactionError::InterleavedInputTrees { index, tree_id });
            }
            seen.push(tree_id);
        }

        // 4. Read the first nullifier and initialize the transaction.
        let first_nullifier = inputs.first().ok_or(TransactionError::NoInputs)?.nullifier;

        Ok(Self {
            inputs,
            outputs: Vec::new(),
            public_transfers: Vec::new(),
            payer,
            blinding_seed: random_blinding(),
            output_tree_id: 0,
            first_nullifier,
            input_tree_ids,
            ring_program_id: None,
            padded_inputs: None,
        })
    }

    /// Stable within each run, the first nullifier follows the new order.
    pub fn move_input_tree_last(&mut self, tree_id: u16) -> Result<&mut Self, TransactionError> {
        if !self.input_tree_ids.contains(&tree_id) || self.input_tree_ids.last() == Some(&tree_id) {
            return Ok(self);
        }
        if self.padded_inputs.is_some() {
            return Err(TransactionError::OutputUtxosAlreadyPadded);
        }
        let (mut inputs, run): (Vec<_>, Vec<_>) = self
            .inputs
            .iter()
            .cloned()
            .partition(|input| input.tree_id != tree_id);
        inputs.extend(run);
        let reordered = Self::new(inputs, self.payer)?;
        self.inputs = reordered.inputs;
        self.first_nullifier = reordered.first_nullifier;
        self.input_tree_ids = reordered.input_tree_ids;
        Ok(self)
    }

    /// Transfer SPL tokens to a recipient shielded address.
    ///
    /// A transfer means to create a new UTXO for the recipient, an output UTXO.
    /// This method adds an output UTXO of asset and amount for the recipient.
    /// Change UTXOs are created during encryption to balance the transaction.
    pub fn transfer(
        &mut self,
        recipient: &ShieldedAddress,
        asset: Address,
        amount: u64,
    ) -> Result<&mut Self, TransactionError> {
        if asset == SOL_MINT {
            return Err(TransactionError::ExpectedSplMint);
        }
        let asset = self
            .inputs
            .iter()
            .find(|input| !input.utxo.owner.is_zero() && input.utxo.asset.asset == asset)
            .map(|input| input.utxo.asset)
            .ok_or(TransactionError::UnknownMint(asset))?;

        self.internal_add_output_utxo(Recipient {
            address: *recipient,
            asset,
            amount,
            ring_program_id: self.ring_program_id,
        })
    }

    /// Transfer SOL to a recipient shielded address.
    pub fn transfer_sol(
        &mut self,
        recipient: &ShieldedAddress,
        amount: u64,
    ) -> Result<&mut Self, TransactionError> {
        self.internal_add_output_utxo(Recipient {
            address: *recipient,
            asset: Mint::SOL,
            amount,
            ring_program_id: self.ring_program_id,
        })
    }

    /// Deposit SPL tokens from the source token account.
    pub fn deposit(
        &mut self,
        asset: Mint,
        amount: u64,
        user_spl_token: Address,
    ) -> Result<&mut Self, TransactionError> {
        if asset.asset == SOL_MINT {
            return Err(TransactionError::ExpectedSplMint);
        }
        // we require mint because we cannot guarantee an input utxo with that Mint
        self.settle(
            asset,
            true,
            amount,
            SettlementTarget::Spl { user_spl_token },
        )
    }

    /// Deposit SOL from the source account.
    pub fn deposit_sol(
        &mut self,
        amount: u64,
        user_sol_account: Address,
    ) -> Result<&mut Self, TransactionError> {
        self.settle(
            Mint::SOL,
            true,
            amount,
            SettlementTarget::Sol { user_sol_account },
        )
    }

    /// Withdraw SPL tokens to the destination token account.
    pub fn withdraw(
        &mut self,
        asset: Address,
        amount: u64,
        user_spl_token: Address,
    ) -> Result<&mut Self, TransactionError> {
        if asset == SOL_MINT {
            return Err(TransactionError::ExpectedSplMint);
        }
        let asset = self
            .inputs
            .iter()
            .find(|input| !input.utxo.owner.is_zero() && input.utxo.asset.asset == asset)
            .map(|input| input.utxo.asset)
            .ok_or(TransactionError::UnknownMint(asset))?;

        self.settle(
            asset,
            false,
            amount,
            SettlementTarget::Spl { user_spl_token },
        )
    }

    /// Withdraw SOL to the destination account.
    pub fn withdraw_sol(
        &mut self,
        amount: u64,
        user_sol_account: Address,
    ) -> Result<&mut Self, TransactionError> {
        self.settle(
            Mint::SOL,
            false,
            amount,
            SettlementTarget::Sol { user_sol_account },
        )
    }
}
