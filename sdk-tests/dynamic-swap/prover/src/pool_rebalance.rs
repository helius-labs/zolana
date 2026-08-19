use std::collections::HashMap;

use crate::{
    bytes_to_decimal_string,
    ffi::{self, CircuitId},
    proof::{negate_and_compress_proof, OrderProof, ProofError},
    utxo::utxo_witness_entries,
    ProofInputUtxo,
};

/// Slot counts of the compiled `pool_rebalance` circuit -- the largest
/// SPP-supported transact shape. Callers pass fully padded slot arrays: real
/// pool notes first, dummy notes (fresh random blindings) trailing, matching
/// the transact the proof rides on.
pub const REBALANCE_INPUT_SLOTS: usize = 5;
pub const REBALANCE_OUTPUT_SLOTS: usize = 4;

/// Proof inputs for the `pool_rebalance` circuit: up to 5 pool notes in, up to
/// 4 pool notes out, dummy-padded to the fixed IN5_OUT4 shape. The circuit
/// checks conservation over the real slots, per-output `booked <= amount`, and
/// `sum(booked_out) = sum(booked_in) + credit` for the public `credit` the
/// program adds to `liquidity_bound`.
#[derive(Debug, Clone)]
pub struct PoolRebalanceProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    /// The pool_authority PDA's owner-hash (`PoolAuthorityOwnerHash`), bound
    /// to every real slot.
    pub pool_authority_owner_hash: [u8; 32],
    /// The pair's destination-asset commitment (`DestinationAsset`).
    pub destination_asset: [u8; 32],
    /// The published surplus (`Credit`); 0 is a pure merge/split/re-blind.
    pub credit: u64,
    /// Input slots, real notes first, dummies trailing.
    pub inputs: [ProofInputUtxo; REBALANCE_INPUT_SLOTS],
    /// Output slots, real notes first, dummies trailing.
    pub outputs: [ProofInputUtxo; REBALANCE_OUTPUT_SLOTS],
    pub external_data_hash: [u8; 32],
}

const INPUT_SLOT_PREFIXES: [&str; REBALANCE_INPUT_SLOTS] = ["In0", "In1", "In2", "In3", "In4"];
const OUTPUT_SLOT_PREFIXES: [&str; REBALANCE_OUTPUT_SLOTS] = ["Out0", "Out1", "Out2", "Out3"];

impl PoolRebalanceProofInputs {
    fn witness(&self) -> ffi::WitnessMap {
        let mut map = HashMap::new();
        map.insert(
            "Public_PublicInputHash".to_string(),
            vec![bytes_to_decimal_string(&self.public_input_hash)],
        );
        map.insert(
            "Public_PrivateTxHash".to_string(),
            vec![bytes_to_decimal_string(&self.private_tx_hash)],
        );
        map.insert(
            "Public_PoolAuthorityOwnerHash".to_string(),
            vec![bytes_to_decimal_string(&self.pool_authority_owner_hash)],
        );
        map.insert(
            "Public_DestinationAsset".to_string(),
            vec![bytes_to_decimal_string(&self.destination_asset)],
        );
        map.insert("Public_Credit".to_string(), vec![self.credit.to_string()]);
        map.insert(
            "ExternalDataHash".to_string(),
            vec![bytes_to_decimal_string(&self.external_data_hash)],
        );
        for (utxo, prefix) in self
            .inputs
            .iter()
            .zip(INPUT_SLOT_PREFIXES)
            .chain(self.outputs.iter().zip(OUTPUT_SLOT_PREFIXES))
        {
            for (key, value) in utxo_witness_entries(utxo, prefix) {
                map.insert(key, value);
            }
        }
        map
    }

    pub fn prove(&self) -> Result<OrderProof, ProofError> {
        negate_and_compress_proof(&ffi::prove(CircuitId::PoolRebalance, &self.witness())?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn sample() -> PoolRebalanceProofInputs {
        PoolRebalanceProofInputs {
            public_input_hash: [1; 32],
            private_tx_hash: [2; 32],
            pool_authority_owner_hash: [3; 32],
            destination_asset: [4; 32],
            credit: 10,
            inputs: std::array::from_fn(|_| ProofInputUtxo::default()),
            outputs: std::array::from_fn(|_| ProofInputUtxo::default()),
            external_data_hash: [5; 32],
        }
    }

    #[test]
    fn witness_key_set_matches_circuit_fields() {
        let witness = sample().witness();
        let keys: HashSet<&str> = witness.keys().map(String::as_str).collect();

        let mut expected: Vec<String> = vec![
            "Public_PublicInputHash".to_string(),
            "Public_PrivateTxHash".to_string(),
            "Public_PoolAuthorityOwnerHash".to_string(),
            "Public_DestinationAsset".to_string(),
            "Public_Credit".to_string(),
            "ExternalDataHash".to_string(),
        ];
        for prefix in INPUT_SLOT_PREFIXES
            .iter()
            .chain(OUTPUT_SLOT_PREFIXES.iter())
        {
            for suffix in [
                "Domain",
                "Owner",
                "Asset",
                "Amount",
                "Blinding",
                "DataHash",
                "RingDataHash",
                "RingProgramID",
            ] {
                expected.push(format!("{prefix}_{suffix}"));
            }
        }

        let expected: HashSet<&str> = expected.iter().map(String::as_str).collect();
        assert_eq!(keys, expected);
    }
}
