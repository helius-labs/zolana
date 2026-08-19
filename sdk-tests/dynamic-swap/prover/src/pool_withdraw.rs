use std::collections::HashMap;

use crate::{
    bytes_to_decimal_string,
    ffi::{self, CircuitId},
    proof::{negate_and_compress_proof, OrderProof, ProofError},
    utxo::utxo_witness_entries,
    ProofInputUtxo,
};

/// Proof inputs for the `pool_withdraw` circuit: 1-in (pool note) / 1-out
/// (pool change), the exact IN1_OUT1 shape. The public `amount` leaves the
/// pool through the transact's SplWithdrawal leg; the change note keeps
/// `booked_in - amount` as its data hash, rejected in-circuit if negative, so
/// a withdrawal can only consume counted value. `amount = 0` re-blinds a
/// public deposit note into a confidential one.
#[derive(Debug, Clone)]
pub struct PoolWithdrawProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    /// The pool_authority PDA's owner-hash (`PoolAuthorityOwnerHash`), bound
    /// to both pool notes.
    pub pool_authority_owner_hash: [u8; 32],
    /// The pair's destination-asset commitment (`DestinationAsset`).
    pub destination_asset: [u8; 32],
    /// The public withdrawn amount.
    pub amount: u64,
    pub pool_in: ProofInputUtxo,
    pub pool_out: ProofInputUtxo,
    pub external_data_hash: [u8; 32],
}

impl PoolWithdrawProofInputs {
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
        map.insert("Public_Amount".to_string(), vec![self.amount.to_string()]);
        map.insert(
            "ExternalDataHash".to_string(),
            vec![bytes_to_decimal_string(&self.external_data_hash)],
        );
        for (key, value) in utxo_witness_entries(&self.pool_in, "PoolIn")
            .into_iter()
            .chain(utxo_witness_entries(&self.pool_out, "PoolOut"))
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> Result<OrderProof, ProofError> {
        negate_and_compress_proof(&ffi::prove(CircuitId::PoolWithdraw, &self.witness())?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn sample() -> PoolWithdrawProofInputs {
        PoolWithdrawProofInputs {
            public_input_hash: [1; 32],
            private_tx_hash: [2; 32],
            pool_authority_owner_hash: [3; 32],
            destination_asset: [4; 32],
            amount: 25,
            pool_in: ProofInputUtxo::default(),
            pool_out: ProofInputUtxo::default(),
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
            "Public_Amount".to_string(),
            "ExternalDataHash".to_string(),
        ];
        for prefix in ["PoolIn", "PoolOut"] {
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
