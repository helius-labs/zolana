use solana_address::Address;

use super::{
    inputs::{merge_ring_data_hash, validate_merge_inputs},
    MergeTransaction,
};
use crate::{error::TransactionError, WalletUtxo};

impl MergeTransaction {
    /// Merge notes without changing their ring state. Every input must carry
    /// the same committed ring-data hash. Omit the output hash to inherit it,
    /// or supply that same hash explicitly. Missing hashes mean zero.
    pub fn new_with_ring(
        inputs: Vec<WalletUtxo>,
        ring_program_id: Address,
        output_ring_data_hash: Option<[u8; 32]>,
    ) -> Result<Self, TransactionError> {
        let validated_inputs = validate_merge_inputs(&inputs, |index, input_utxo| {
            if input_utxo.utxo.ring_program_id != Some(ring_program_id) {
                return Err(TransactionError::MergeInputRingMismatch { index });
            }
            if input_utxo.data_hash.is_some() || input_utxo.utxo.data.utxo_data().is_some() {
                return Err(TransactionError::MergeInputHasData { index });
            }
            Ok(())
        })?;
        let output_ring_data_hash = merge_ring_data_hash(
            inputs
                .iter()
                .enumerate()
                .filter(|(_, input)| !input.utxo.owner.is_zero())
                .map(|(index, input)| (index, input.ring_data_hash)),
            output_ring_data_hash,
        )?;

        Ok(Self {
            output_tree_id: WalletUtxo::default_output_tree_id(&inputs),
            inputs,
            validated_inputs,
            expiry_unix_ts: u64::MAX,
            ring_program_id: Some(ring_program_id),
            output_ring_data_hash,
        })
    }
}
