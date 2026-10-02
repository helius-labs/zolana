use crate::{error::TransactionError, WalletUtxo};
use solana_address::Address;

mod blinding;
mod encryption;
mod inputs;
mod ring;
mod transaction;

pub use blinding::{
    merge_dummy_nullifier, merge_output_blinding, merge_private_tx_blinding,
    DOMAIN_MERGE_DUMMY_NULLIFIER, DOMAIN_MERGE_OUTPUT_BLINDING_V1,
};
pub use transaction::MergeProofInputs;
pub use zolana_interface::instruction::instruction_data::merge_transact::{
    merge_circuit_width, MAX_MERGE_INPUTS, MERGE_DEFAULT_INPUT_COUNT, MERGE_SUPPORTED_INPUT_COUNTS,
};

use inputs::{validate_merge_inputs, MergeInputs};

#[derive(Clone)]
pub struct MergeTransaction {
    inputs: Vec<WalletUtxo>,
    validated_inputs: MergeInputs,
    expiry_unix_ts: u64,
    output_tree_id: u16,
    ring_program_id: Option<Address>,
    output_ring_data_hash: Option<[u8; 32]>,
    compact_padding: bool,
}

impl MergeTransaction {
    pub fn new(inputs: Vec<WalletUtxo>) -> Result<Self, TransactionError> {
        let validated_inputs = validate_merge_inputs(&inputs, |index, input_utxo| {
            if input_utxo.utxo.ring_program_id.is_some() {
                return Err(TransactionError::MergeInputRingMismatch { index });
            }
            if input_utxo.data_hash.is_some()
                || input_utxo.ring_data_hash.is_some()
                || !input_utxo.utxo.data.is_empty()
            {
                return Err(TransactionError::MergeInputHasData { index });
            }
            Ok(())
        })?;

        Ok(Self {
            inputs,
            validated_inputs,
            expiry_unix_ts: u64::MAX,
            output_tree_id: 0,
            ring_program_id: None,
            output_ring_data_hash: None,
            compact_padding: false,
        })
    }

    /// Like [`new`](Self::new), but pads the circuit's unused slots with
    /// compact padding instead of deterministic dummies. Compact padding is
    /// left out of the instruction and costs no nullifier account or queue
    /// entry, but the merge then reveals its real input count.
    pub fn new_compact(inputs: Vec<WalletUtxo>) -> Result<Self, TransactionError> {
        let mut merge = Self::new(inputs)?;
        merge.compact_padding = true;
        Ok(merge)
    }

    pub fn with_expiry(mut self, expiry_unix_ts: u64) -> Self {
        self.expiry_unix_ts = expiry_unix_ts;
        self
    }

    #[must_use]
    pub fn with_output_tree_id(mut self, output_tree_id: u16) -> Self {
        self.output_tree_id = output_tree_id;
        self
    }
}
