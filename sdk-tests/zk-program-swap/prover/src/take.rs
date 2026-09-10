use std::collections::HashMap;

use zolana_transaction::ProofInputUtxo;

use crate::{
    bytes_to_decimal_string, ffi,
    proof::{negate_and_compress_proof, OrderProof, ProofError},
    utxo::utxo_witness_entries,
    CircuitId, OrderTermsProofInput,
};

#[derive(Debug, Clone)]
pub struct TakeProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub first_nullifier: [u8; 32],
    pub order: OrderTermsProofInput,
    pub order_utxo: ProofInputUtxo,
    pub taker_in: ProofInputUtxo,
    pub source_output: ProofInputUtxo,
    pub destination_output: ProofInputUtxo,
    pub external_data_hash: [u8; 32],
    pub private_tx_blinding: [u8; 32],
}

impl TakeProofInputs {
    fn witness(&self) -> ffi::WitnessMap {
        let scalars: [(&str, [u8; 32]); 5] = [
            ("Public_PublicInputHash", self.public_input_hash),
            ("Public_PrivateTxHash", self.private_tx_hash),
            ("Public_FirstNullifier", self.first_nullifier),
            ("Core_ExternalDataHash", self.external_data_hash),
            ("Core_PrivateTxBlinding", self.private_tx_blinding),
        ];
        let mut map = HashMap::new();
        for (key, value) in scalars.iter() {
            map.insert(key.to_string(), vec![bytes_to_decimal_string(value)]);
        }
        for (key, value) in self
            .order
            .witness_entries("Core_Order")
            .into_iter()
            .chain(utxo_witness_entries(&self.order_utxo, "Core_OrderUtxo"))
            .chain(utxo_witness_entries(&self.taker_in, "Core_TakerIn"))
            .chain(utxo_witness_entries(
                &self.source_output,
                "Core_SourceOutput",
            ))
            .chain(utxo_witness_entries(
                &self.destination_output,
                "Core_DestinationOutput",
            ))
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> Result<OrderProof, ProofError> {
        negate_and_compress_proof(&ffi::prove(CircuitId::Take, &self.witness())?)
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

    fn sample() -> TakeProofInputs {
        TakeProofInputs {
            public_input_hash: [1; 32],
            private_tx_hash: [2; 32],
            first_nullifier: [10; 32],
            order: OrderTermsProofInput {
                destination_asset: [3; 32],
                destination_amount: 7,
                maker_owner_hash: [4; 32],
                maker_viewing_pk: [5; 33],
                expiry: 9,
                taker_pk_fe: [6; 32],
                take_mode: TAKE_MODE_DERIVED,
            },
            order_utxo: ProofInputUtxo::default(),
            taker_in: ProofInputUtxo::default(),
            source_output: ProofInputUtxo::default(),
            destination_output: ProofInputUtxo::default(),
            external_data_hash: [7; 32],
            private_tx_blinding: [8; 32],
        }
    }

    #[test]
    fn witness_key_set_matches_circuit_fields() {
        let witness = sample().witness();
        let keys: HashSet<String> = witness.keys().cloned().collect();

        let mut expected: Vec<String> = vec![
            "Public_PublicInputHash".to_string(),
            "Public_PrivateTxHash".to_string(),
            "Public_FirstNullifier".to_string(),
            "Core_ExternalDataHash".to_string(),
            "Core_PrivateTxBlinding".to_string(),
        ];
        expected.extend(expected_order_terms_witness_keys("Core_Order"));
        for prefix in [
            "Core_OrderUtxo",
            "Core_TakerIn",
            "Core_SourceOutput",
            "Core_DestinationOutput",
        ] {
            expected.extend(expected_utxo_witness_keys(prefix));
        }

        assert_eq!(keys, expected.into_iter().collect::<HashSet<String>>());
    }
}
