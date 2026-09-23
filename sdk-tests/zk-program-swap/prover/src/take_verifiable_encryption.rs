use std::collections::HashMap;

use zolana_client::ProofInputUtxo;
use zolana_gnark_ffi_prover::{decimal, utxo_proof_inputs, ProofInputMap};

use crate::{CircuitId, OrderProof, OrderTermsProofInput, PROVER};

pub const TAKE_ENC_KDF_DOMAIN: u64 = 0x5357_4150_5441_4b45;

#[derive(Debug, Clone)]
pub struct TakeVerifiableEncryptionProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub order: OrderTermsProofInput,
    pub taker_nullifier_pk: [u8; 32],
    pub order_utxo: ProofInputUtxo,
    pub taker_in: ProofInputUtxo,
    pub source_output: ProofInputUtxo,
    pub destination_output: ProofInputUtxo,
    pub external_data_hash: [u8; 32],
    pub private_tx_blinding: [u8; 32],
}

impl TakeVerifiableEncryptionProofInputs {
    fn witness(&self) -> ProofInputMap {
        let scalars: [(&str, [u8; 32]); 5] = [
            ("Public_PublicInputHash", self.public_input_hash),
            ("Public_PrivateTxHash", self.private_tx_hash),
            ("Core_ExternalDataHash", self.external_data_hash),
            ("Core_PrivateTxBlinding", self.private_tx_blinding),
            ("TakerNullifierPk", self.taker_nullifier_pk),
        ];
        let mut map = HashMap::new();
        for (key, value) in scalars.iter() {
            map.insert(key.to_string(), vec![decimal(value)]);
        }
        for (key, value) in self
            .order
            .witness_entries("Core_Order")
            .into_iter()
            .chain(utxo_proof_inputs(&self.order_utxo, "Core_OrderUtxo"))
            .chain(utxo_proof_inputs(&self.taker_in, "Core_TakerIn"))
            .chain(utxo_proof_inputs(&self.source_output, "Core_SourceOutput"))
            .chain(utxo_proof_inputs(
                &self.destination_output,
                "Core_DestinationOutput",
            ))
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> zolana_gnark_ffi_prover::Result<OrderProof> {
        Ok(PROVER
            .prove(CircuitId::TakeVerifiableEncryption, &self.witness())?
            .compress()?
            .into())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use zolana_gnark_ffi_prover::utxo_proof_input_keys;

    use super::*;
    use crate::{order_terms::expected_order_terms_witness_keys, TAKE_MODE_VERIFIABLE};

    fn sample() -> TakeVerifiableEncryptionProofInputs {
        TakeVerifiableEncryptionProofInputs {
            public_input_hash: [1; 32],
            private_tx_hash: [2; 32],
            order: OrderTermsProofInput {
                destination_asset: [3; 32],
                destination_amount: 7,
                maker_owner_hash: [4; 32],
                maker_viewing_pk: [5; 33],
                expiry: 9,
                taker_pk_fe: [6; 32],
                take_mode: TAKE_MODE_VERIFIABLE,
            },
            taker_nullifier_pk: [7; 32],
            order_utxo: ProofInputUtxo::default(),
            taker_in: ProofInputUtxo::default(),
            source_output: ProofInputUtxo::default(),
            destination_output: ProofInputUtxo::default(),
            external_data_hash: [8; 32],
            private_tx_blinding: [9; 32],
        }
    }

    #[test]
    fn witness_key_set_matches_circuit_fields() {
        let witness = sample().witness();
        let keys: HashSet<String> = witness.keys().cloned().collect();

        let mut expected: Vec<String> = vec![
            "Public_PublicInputHash".to_string(),
            "Public_PrivateTxHash".to_string(),
            "Core_ExternalDataHash".to_string(),
            "Core_PrivateTxBlinding".to_string(),
            "TakerNullifierPk".to_string(),
        ];
        expected.extend(expected_order_terms_witness_keys("Core_Order"));
        for prefix in [
            "Core_OrderUtxo",
            "Core_TakerIn",
            "Core_SourceOutput",
            "Core_DestinationOutput",
        ] {
            expected.extend(utxo_proof_input_keys(prefix));
        }

        assert_eq!(keys, expected.into_iter().collect::<HashSet<String>>());
    }
}
