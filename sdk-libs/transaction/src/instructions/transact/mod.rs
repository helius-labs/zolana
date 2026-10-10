//! Client-side transact assembly in two layers. The low level is
//! [`SppProofInputs`] (the assembled transaction sent to the prover), written
//! as a struct literal with explicitly encoded output slots; it serves custom
//! UTXOs (ring/swap flows). The high level is
//! [`ConfidentialTransaction`], which validates input order at construction,
//! derives the change outputs and pads both inputs and outputs to a declared or
//! automatically selected [`Shape`], then encrypts the result into [`SppProofInputs`].
//! [`PrivateTxHash`] produces the `private_tx_hash` shared as a public input by
//! the SPP and ring proofs, and [`transact_message_hash`] the digest a P256
//! owner signs over it and the external data hash.

mod cache;
mod encryption;
pub mod external_data;
mod inputs;
mod outputs;
mod ring;
mod settlement;
pub mod shape;
pub mod transaction;

use solana_address::Address;
use zolana_interface::{pda, MAX_INPUT_TREES};
use zolana_keypair::{shielded::ShieldedAddress, viewing_key::random_blinding};
use zolana_program::instruction::{
    TransactInterfaceTransferAccounts, TransactSolTransferAccounts, TransactSplWithdrawalAccounts,
};

pub use crate::indexer_types::{OutputContext, OutputSlot, ShieldedTransaction};
pub use crate::utxo::SppProofOutputUtxo;
pub use cache::{cache_bound_external_data_hash, cache_write_slots};
pub use encryption::ResolvedOwnerTag;
pub use external_data::{ExternalData, SettlementTransfer};
pub use inputs::pad_input_utxos;
pub use outputs::Recipient;
pub use ring::inputs_require_p256;
pub use settlement::{
    asset_field, signed_magnitude_to_field, PublicTransferRequest, PublicTransfers,
    SettlementTarget, BN254_MODULUS_DEC,
};
pub use shape::{
    auto_shapes, canonical_shape, resolve_shape, Shape, MAX_SPEND_INPUTS, SPP_SUPPORTED_SHAPES,
};
pub(crate) use transaction::real_slot_after_dummy;
pub use transaction::{transact_message_hash, CacheAccounts, PrivateTxHash, SppProofInputs};

use ring::sender_owner_tag;

use crate::{error::TransactionError, utxo::SppProofInputUtxo, Mint, WalletUtxo, SOL_MINT};

/// Build a confidential transaction from ordered input UTXOs.
///
/// Typical flows:
/// - Transfer: [`new`](Self::new) → [`transfer`](Self::transfer) → [`encrypt`](Self::encrypt).
/// - Deposit: [`new`](Self::new) → [`deposit`](Self::deposit) → [`encrypt`](Self::encrypt).
/// - Withdraw: [`new`](Self::new) → [`withdraw`](Self::withdraw) → [`encrypt`](Self::encrypt).
/// - Program-owned inputs: [`from_proof_inputs`](Self::from_proof_inputs) →
///   [`add_output_utxo`](Self::add_output_utxo) → [`encrypt`](Self::encrypt).
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
    inputs: Vec<SppProofInputUtxo>,
    outputs: Vec<SppProofOutputUtxo>,
    public_transfers: Vec<PublicTransferRequest>,
    payer: Address,
    blinding_seed: [u8; 32],
    output_tree_id: u16,
    first_nullifier: [u8; 32],
    input_tree_ids: Vec<u16>,
    ring_program_id: Option<Address>,
    padded_inputs: Option<Vec<SppProofInputUtxo>>,
    compact_padding: bool,
}

impl ConfidentialTransaction {
    pub fn inputs(&self) -> &[SppProofInputUtxo] {
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
    /// 3. Read the first nullifier and initialize the transaction with a fresh
    ///    blinding seed and no outputs or public transfers.
    pub fn new(inputs: Vec<WalletUtxo>, payer: Address) -> Result<Self, TransactionError> {
        Self::from_validated_inputs(
            inputs.into_iter().map(SppProofInputUtxo::from).collect(),
            payer,
        )
    }

    fn from_validated_inputs(
        inputs: Vec<SppProofInputUtxo>,
        payer: Address,
    ) -> Result<Self, TransactionError> {
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

        // 3. Read the first nullifier and initialize the transaction.
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
            compact_padding: false,
        })
    }

    /// Like [`new`](Self::new), but pads unused slots with compact padding
    /// instead of random dummies. Compact padding is left out of the
    /// instruction and costs no nullifier account, queue entry or tree leaf, but
    /// the transaction then reveals its real input and output counts.
    pub fn new_compact(inputs: Vec<WalletUtxo>, payer: Address) -> Result<Self, TransactionError> {
        let mut transaction = Self::new(inputs, payer)?;
        transaction.compact_padding = true;
        Ok(transaction)
    }

    /// Like [`new_compact`](Self::new_compact), for inputs a program SDK
    /// assembles itself, such as a program-owned UTXO it reconstructs from its
    /// own state, rather than notes the indexer returned to a wallet. The
    /// transaction still picks the shape, pads, derives every output blinding
    /// and encrypts.
    ///
    /// Steps:
    /// 1. Reject compact padding, which the transaction adds itself, and
    ///    cached inputs, whose cache accounts [`encrypt`](Self::encrypt) does
    ///    not populate.
    /// 2. Validate and pad like [`new_compact`](Self::new_compact).
    pub fn from_proof_inputs(
        inputs: Vec<SppProofInputUtxo>,
        payer: Address,
    ) -> Result<Self, TransactionError> {
        // 1. Reject padding and cached inputs.
        for (index, input) in inputs.iter().enumerate() {
            if input.compact {
                return Err(TransactionError::CompactProofInput { index });
            }
            if input.cache_slot.is_some() {
                return Err(TransactionError::CachedProofInput { index });
            }
        }
        // 2. Validate and pad like `new_compact`.
        let mut transaction = Self::from_validated_inputs(inputs, payer)?;
        transaction.compact_padding = true;
        Ok(transaction)
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

    /// Withdraw `amount` of `asset` to the public account `recipient` and
    /// return the settlement accounts the `transact` instruction takes for it,
    /// as `withdrawal_settlement` derives them. The token account of an SPL
    /// withdrawal must exist when the transaction lands.
    pub fn withdraw_to(
        &mut self,
        asset: Address,
        amount: u64,
        recipient: Address,
        token_program: Option<Address>,
    ) -> Result<TransactInterfaceTransferAccounts, TransactionError> {
        let (target, accounts) = withdrawal_settlement(asset, recipient, token_program)?;
        match target {
            SettlementTarget::Sol { user_sol_account } => {
                self.withdraw_sol(amount, user_sol_account)?
            }
            SettlementTarget::Spl { user_spl_token } => {
                self.withdraw(asset, amount, user_spl_token)?
            }
        };
        Ok(accounts)
    }
}

/// Where a withdrawal of `asset` to the public account `recipient` settles,
/// and the settlement accounts the `transact` instruction takes for it. SOL
/// goes to `recipient` itself. An SPL mint goes to `recipient`'s associated
/// token account under `token_program`, the mint's token program, which must
/// be `None` for SOL.
fn withdrawal_settlement(
    asset: Address,
    recipient: Address,
    token_program: Option<Address>,
) -> Result<(SettlementTarget, TransactInterfaceTransferAccounts), TransactionError> {
    if asset == SOL_MINT {
        if let Some(token_program) = token_program {
            return Err(TransactionError::UnexpectedSolTokenProgram { token_program });
        }
        return Ok((
            SettlementTarget::Sol {
                user_sol_account: recipient,
            },
            TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts { recipient }),
        ));
    }
    let token_program =
        token_program.ok_or(TransactionError::MissingSplTokenProgram { mint: asset })?;
    let user_token_account =
        pda::associated_token_address_with_program(&recipient, &asset, &token_program);
    Ok((
        SettlementTarget::Spl {
            user_spl_token: user_token_account,
        },
        TransactInterfaceTransferAccounts::SplWithdrawal(TransactSplWithdrawalAccounts {
            mint: asset,
            spl_interface: pda::spl_interface(&asset),
            user_token_account,
            token_program,
        }),
    ))
}
