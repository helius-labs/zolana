use std::collections::HashMap;

use crate::{
    bytes_to_decimal_string,
    ffi::{self, CircuitId},
    proof::{negate_and_compress_proof, OrderProof, ProofError},
    utxo::utxo_witness_entries,
    ProofInputUtxo,
};

/// Proof inputs for the `pool_update` circuit, shared by `deposit_liquidity`
/// and `withdraw_liquidity`. The pool credit/debit is balanced against an
/// authority-owned note (`auth_in`/`auth_out`) of the same asset entirely
/// inside the shielded set, so no amount is ever public -- see `pool_update.go`
/// for why there is no `Delta` witness or public settlement leg.
#[derive(Debug, Clone)]
pub struct PoolUpdateProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    /// The pool-input UTXO's own hash -- the account's current on-chain
    /// `Liquidity.available_hash`, asserted equal in-circuit to `Hash(pool_in)`.
    pub pool_in_hash: [u8; 32],
    pub destination_asset: [u8; 32],
    pub reserved_liability: u64,
    pub slot_value: u64,
    pub available_slots: u64,
    pub refresh_capacity: bool,
    pub pool_in: ProofInputUtxo,
    pub auth_in: ProofInputUtxo,
    pub pool_out: ProofInputUtxo,
    pub auth_out: ProofInputUtxo,
    pub external_data_hash: [u8; 32],
}

impl PoolUpdateProofInputs {
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
            "Public_PoolInHash".to_string(),
            vec![bytes_to_decimal_string(&self.pool_in_hash)],
        );
        map.insert(
            "Public_DestinationAsset".to_string(),
            vec![bytes_to_decimal_string(&self.destination_asset)],
        );
        map.insert(
            "Public_ReservedLiability".to_string(),
            vec![self.reserved_liability.to_string()],
        );
        map.insert(
            "Public_SlotValue".to_string(),
            vec![self.slot_value.to_string()],
        );
        map.insert(
            "Public_AvailableSlots".to_string(),
            vec![self.available_slots.to_string()],
        );
        map.insert(
            "Public_RefreshCapacity".to_string(),
            vec![u8::from(self.refresh_capacity).to_string()],
        );
        map.insert(
            "ExternalDataHash".to_string(),
            vec![bytes_to_decimal_string(&self.external_data_hash)],
        );
        for (key, value) in utxo_witness_entries(&self.pool_in, "PoolIn")
            .into_iter()
            .chain(utxo_witness_entries(&self.auth_in, "AuthIn"))
            .chain(utxo_witness_entries(&self.pool_out, "PoolOut"))
            .chain(utxo_witness_entries(&self.auth_out, "AuthOut"))
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> Result<OrderProof, ProofError> {
        negate_and_compress_proof(&ffi::prove(CircuitId::PoolUpdate, &self.witness())?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn sample() -> PoolUpdateProofInputs {
        PoolUpdateProofInputs {
            public_input_hash: [1; 32],
            private_tx_hash: [2; 32],
            pool_in_hash: [3; 32],
            destination_asset: [4; 32],
            reserved_liability: 10,
            slot_value: 5,
            available_slots: 2,
            refresh_capacity: true,
            pool_in: ProofInputUtxo::default(),
            auth_in: ProofInputUtxo::default(),
            pool_out: ProofInputUtxo::default(),
            auth_out: ProofInputUtxo::default(),
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
            "Public_PoolInHash".to_string(),
            "Public_DestinationAsset".to_string(),
            "Public_ReservedLiability".to_string(),
            "Public_SlotValue".to_string(),
            "Public_AvailableSlots".to_string(),
            "Public_RefreshCapacity".to_string(),
            "ExternalDataHash".to_string(),
        ];
        for prefix in ["PoolIn", "AuthIn", "PoolOut", "AuthOut"] {
            for suffix in [
                "Domain",
                "Owner",
                "Asset",
                "Amount",
                "Blinding",
                "DataHash",
                "ZoneDataHash",
                "ZoneProgramID",
            ] {
                expected.push(format!("{prefix}_{suffix}"));
            }
        }

        let expected: HashSet<&str> = expected.iter().map(String::as_str).collect();
        assert_eq!(keys, expected);
    }
}
