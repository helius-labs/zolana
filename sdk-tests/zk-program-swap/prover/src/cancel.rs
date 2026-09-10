use std::collections::HashMap;

use zolana_transaction::ProofInputUtxo;

use crate::{
    bytes_to_decimal_string, ffi,
    proof::{negate_and_compress_proof, OrderProof, ProofError},
    utxo::utxo_witness_entries,
    CircuitId, OrderTermsProofInput,
};

#[derive(Debug, Clone)]
pub struct CancelProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub order: OrderTermsProofInput,
    pub maker_owner_pk_field: [u8; 32],
    pub maker_nullifier_pk: [u8; 32],
    pub order_utxo: ProofInputUtxo,
    pub source_output: ProofInputUtxo,
    pub external_data_hash: [u8; 32],
    pub private_tx_blinding: [u8; 32],
}

impl CancelProofInputs {
    fn witness(&self) -> ffi::WitnessMap {
        let scalars: [(&str, [u8; 32]); 6] = [
            ("Public_PublicInputHash", self.public_input_hash),
            ("Public_PrivateTxHash", self.private_tx_hash),
            ("MakerOwnerPkField", self.maker_owner_pk_field),
            ("MakerNullifierPk", self.maker_nullifier_pk),
            ("ExternalDataHash", self.external_data_hash),
            ("PrivateTxBlinding", self.private_tx_blinding),
        ];
        let mut map = HashMap::new();
        for (key, value) in scalars.iter() {
            map.insert(key.to_string(), vec![bytes_to_decimal_string(value)]);
        }
        for (key, value) in self
            .order
            .witness_entries("Order")
            .into_iter()
            .chain(utxo_witness_entries(&self.order_utxo, "OrderUtxo"))
            .chain(utxo_witness_entries(&self.source_output, "SourceOutput"))
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> Result<OrderProof, ProofError> {
        negate_and_compress_proof(&ffi::prove(CircuitId::Cancel, &self.witness())?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::{
        order_terms::expected_order_terms_witness_keys, utxo::expected_utxo_witness_keys,
        TAKE_MODE_DERIVED,
    };

    fn sample() -> CancelProofInputs {
        CancelProofInputs {
            public_input_hash: [1; 32],
            private_tx_hash: [2; 32],
            order: OrderTermsProofInput {
                destination_asset: [3; 32],
                destination_amount: 7,
                maker_owner_hash: [4; 32],
                maker_viewing_pk: [5; 33],
                expiry: 9,
                taker_pk_fe: [6; 32],
                take_mode: TAKE_MODE_DERIVED,
            },
            maker_owner_pk_field: [7; 32],
            maker_nullifier_pk: [8; 32],
            order_utxo: ProofInputUtxo::default(),
            source_output: ProofInputUtxo::default(),
            external_data_hash: [9; 32],
            private_tx_blinding: [10; 32],
        }
    }

    #[test]
    fn witness_key_set_matches_circuit_fields() {
        let witness = sample().witness();
        let keys: HashSet<String> = witness.keys().cloned().collect();

        let mut expected: Vec<String> = vec![
            "Public_PublicInputHash".to_string(),
            "Public_PrivateTxHash".to_string(),
            "MakerOwnerPkField".to_string(),
            "MakerNullifierPk".to_string(),
            "ExternalDataHash".to_string(),
            "PrivateTxBlinding".to_string(),
        ];
        expected.extend(expected_order_terms_witness_keys("Order"));
        expected.extend(expected_utxo_witness_keys("OrderUtxo"));
        expected.extend(expected_utxo_witness_keys("SourceOutput"));

        assert_eq!(keys, expected.into_iter().collect::<HashSet<String>>());
    }
}
