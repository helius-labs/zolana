use std::collections::HashMap;

use zolana_client::ProofInputUtxo;
use zolana_gnark_prover::{decimal, utxo_witness_entries, WitnessMap};

use crate::{CircuitId, OrderProof, OrderTermsProofInput, PROVER};

#[derive(Debug, Clone)]
pub struct MakeProofInputs {
    pub private_tx_hash: [u8; 32],
    pub order: OrderTermsProofInput,
    pub order_utxo: ProofInputUtxo,
    pub change: ProofInputUtxo,
    pub source_input_hash: [u8; 32],
    pub external_data_hash: [u8; 32],
    pub private_tx_blinding: [u8; 32],
}

impl MakeProofInputs {
    fn witness(&self) -> WitnessMap {
        let scalars: [(&str, [u8; 32]); 4] = [
            ("PrivateTxHash", self.private_tx_hash),
            ("SourceInputHash", self.source_input_hash),
            ("ExternalDataHash", self.external_data_hash),
            ("PrivateTxBlinding", self.private_tx_blinding),
        ];
        let mut map = HashMap::new();
        for (key, value) in scalars.iter() {
            map.insert(key.to_string(), vec![decimal(value)]);
        }
        for (key, value) in self
            .order
            .witness_entries("Order")
            .into_iter()
            .chain(utxo_witness_entries(&self.order_utxo, "OrderUtxo"))
            .chain(utxo_witness_entries(&self.change, "Change"))
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> zolana_gnark_prover::Result<OrderProof> {
        Ok(PROVER
            .prove(CircuitId::Make, &self.witness())?
            .compress()?
            .into())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use zolana_gnark_prover::expected_utxo_witness_keys;

    use super::*;
    use crate::{order_terms::expected_order_terms_witness_keys, TAKE_MODE_DERIVED};

    fn sample() -> MakeProofInputs {
        MakeProofInputs {
            private_tx_hash: [1; 32],
            order: OrderTermsProofInput {
                destination_asset: [2; 32],
                destination_amount: 7,
                maker_owner_hash: [3; 32],
                maker_viewing_pk: [4; 33],
                expiry: 9,
                taker_pk_fe: [5; 32],
                take_mode: TAKE_MODE_DERIVED,
            },
            order_utxo: ProofInputUtxo::default(),
            change: ProofInputUtxo::default(),
            source_input_hash: [6; 32],
            external_data_hash: [7; 32],
            private_tx_blinding: [8; 32],
        }
    }

    #[test]
    fn witness_key_set_matches_circuit_fields() {
        let witness = sample().witness();
        let keys: HashSet<String> = witness.keys().cloned().collect();

        let mut expected: Vec<String> = vec![
            "PrivateTxHash".to_string(),
            "SourceInputHash".to_string(),
            "ExternalDataHash".to_string(),
            "PrivateTxBlinding".to_string(),
        ];
        expected.extend(expected_order_terms_witness_keys("Order"));
        expected.extend(expected_utxo_witness_keys("OrderUtxo"));
        expected.extend(expected_utxo_witness_keys("Change"));

        assert_eq!(keys, expected.into_iter().collect::<HashSet<String>>());
    }
}
