use solana_address::Address;
use zolana_keypair::ShieldedAddress;

use super::{
    shape::canonical_shape,
    transaction::{padding_independent_private_tx_hash, private_tx_blinding},
    ConfidentialTransaction, ResolvedOwnerTag, SettlementTransfer, SppProofOutputUtxo,
};
use crate::{
    error::TransactionError,
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding, SppProofInputUtxo},
};

/// A transaction with its final slots, output blindings, owner tags and public
/// transfers, prepared without key material. Every commitment and the
/// padding-independent private transaction hash are fixed; only the output
/// ciphertexts and the transaction viewing key are missing. The key holder
/// completes it with [`encrypt`](Self::encrypt).
#[derive(Clone)]
pub struct FinalizedTransaction {
    pub(super) input_utxos: Vec<SppProofInputUtxo>,
    pub(super) output_utxos: Vec<SppProofOutputUtxo>,
    pub(super) blinding_seed: [u8; 32],
    pub(super) output_tree_id: u16,
    pub(super) payer: Address,
    pub(super) expiry_unix_ts: u64,
    pub(super) sender: ShieldedAddress,
    pub(super) padding_owner: ShieldedAddress,
    pub(super) owner_tags: Vec<ResolvedOwnerTag>,
    pub(super) interface_transfers: Vec<SettlementTransfer>,
}

impl ConfidentialTransaction {
    /// Consume the transaction and fix everything that needs no key material.
    ///
    /// Steps:
    /// 1. If not already finalized, select a shape, convert wallet inputs and pad
    ///    the input and output slots.
    /// 2. Derive and assign output blindings using the final slot order.
    /// 3. Resolve output owner tags and public settlement transfers.
    pub fn finalize(
        mut self,
        sender: &ShieldedAddress,
    ) -> Result<FinalizedTransaction, TransactionError> {
        // 1. Select a shape and finalize the input and output slots if needed.
        if self.padded_inputs.is_none() {
            let n_in = self.inputs.len();
            let mut n_out = self.outputs.len();
            for asset in self.assets(&self.outputs)? {
                if self.change(&asset)? > 0 {
                    n_out = n_out
                        .checked_add(1)
                        .ok_or(TransactionError::TooManyOutputs)?;
                }
            }
            let shape = canonical_shape(n_in, n_out)?;
            self.pad_utxos(shape, sender)?;
        }
        // 2. Derive and assign output blindings using the final slot order.
        let output_blinding_seed =
            derive_output_blinding_seed(&self.first_nullifier, &self.blinding_seed)?;
        for (index, output) in self.outputs.iter_mut().enumerate() {
            let index = u32::try_from(index).map_err(|_| TransactionError::TooManyOutputs)?;
            output.blinding = derive_transact_output_blinding(
                &self.first_nullifier,
                &output_blinding_seed,
                index,
            )?;
        }
        // 3. Resolve output owner tags and public settlement transfers.
        let padding_owner = self.padding_owner(sender)?;
        let owner_tags = self.owner_tags(&sender.signing_pubkey, Some(&padding_owner))?;
        let interface_transfers = self.interface_transfers()?;

        Ok(FinalizedTransaction {
            input_utxos: self.padded_inputs.ok_or(TransactionError::NoInputs)?,
            output_utxos: self.outputs,
            blinding_seed: self.blinding_seed,
            output_tree_id: self.output_tree_id,
            payer: self.payer,
            expiry_unix_ts: u64::MAX,
            sender: *sender,
            padding_owner,
            owner_tags,
            interface_transfers,
        })
    }
}

impl FinalizedTransaction {
    pub fn input_utxos(&self) -> &[SppProofInputUtxo] {
        &self.input_utxos
    }

    pub fn output_utxos(&self) -> &[SppProofOutputUtxo] {
        &self.output_utxos
    }

    pub fn blinding_seed(&self) -> &[u8; 32] {
        &self.blinding_seed
    }

    pub fn output_tree_id(&self) -> u16 {
        self.output_tree_id
    }

    pub fn payer(&self) -> Address {
        self.payer
    }

    pub fn sender(&self) -> &ShieldedAddress {
        &self.sender
    }

    pub fn padding_owner(&self) -> &ShieldedAddress {
        &self.padding_owner
    }

    pub fn owner_tags(&self) -> &[ResolvedOwnerTag] {
        &self.owner_tags
    }

    pub fn interface_transfers(&self) -> &[SettlementTransfer] {
        &self.interface_transfers
    }

    pub fn expiry_unix_ts(&self) -> u64 {
        self.expiry_unix_ts
    }

    #[must_use]
    pub fn with_expiry_unix_ts(mut self, expiry_unix_ts: u64) -> Self {
        self.expiry_unix_ts = expiry_unix_ts;
        self
    }

    pub fn first_nullifier(&self) -> Result<[u8; 32], TransactionError> {
        Ok(self
            .input_utxos
            .first()
            .ok_or(TransactionError::NoInputs)?
            .nullifier())
    }

    pub fn private_tx_blinding(&self) -> Result<[u8; 32], TransactionError> {
        private_tx_blinding(&self.input_utxos, &self.blinding_seed)
    }

    /// Commitment of every output slot, dummies included, in tree-append order.
    pub fn output_hashes(&self) -> Result<Vec<[u8; 32]>, TransactionError> {
        self.output_utxos
            .iter()
            .map(|output| output.hash(self.output_tree_id))
            .collect()
    }

    pub fn padding_independent_private_tx_hash(&self) -> Result<[u8; 32], TransactionError> {
        padding_independent_private_tx_hash(
            &self.input_utxos,
            &self.output_utxos,
            self.output_tree_id,
            &self.blinding_seed,
        )
    }
}
