use std::collections::HashMap;

use zolana_transaction::ProofInputUtxo;

use crate::{
    bytes_to_decimal_string, ffi,
    proof::{negate_and_compress_proof, ProofError, TimelockProof},
    utxo::utxo_witness_entries,
    CircuitId, EscrowTermsProofInput,
};

#[derive(Debug, Clone)]
pub struct EscrowProofInputs {
    pub private_tx_hash: [u8; 32],
    pub terms: EscrowTermsProofInput,
    pub escrow_utxo: ProofInputUtxo,
    pub change: ProofInputUtxo,
    pub source_input_hash: [u8; 32],
    pub external_data_hash: [u8; 32],
    pub private_tx_blinding: [u8; 32],
}

impl EscrowProofInputs {
    fn witness(&self) -> ffi::WitnessMap {
        let scalars: [(&str, [u8; 32]); 4] = [
            ("PrivateTxHash", self.private_tx_hash),
            ("SourceInputHash", self.source_input_hash),
            ("ExternalDataHash", self.external_data_hash),
            ("PrivateTxBlinding", self.private_tx_blinding),
        ];
        let mut map = HashMap::new();
        for (key, value) in scalars.iter() {
            map.insert(key.to_string(), vec![bytes_to_decimal_string(value)]);
        }
        for (key, value) in self
            .terms
            .witness_entries("Terms")
            .into_iter()
            .chain(utxo_witness_entries(&self.escrow_utxo, "EscrowUtxo"))
            .chain(utxo_witness_entries(&self.change, "Change"))
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> Result<TimelockProof, ProofError> {
        negate_and_compress_proof(&ffi::prove(CircuitId::Escrow, &self.witness())?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::{
        escrow_terms::expected_escrow_terms_witness_keys, utxo::expected_utxo_witness_keys,
    };

    fn sample() -> EscrowProofInputs {
        EscrowProofInputs {
            private_tx_hash: [1; 32],
            terms: EscrowTermsProofInput {
                owner_hash: [2; 32],
                unlock: 42,
            },
            escrow_utxo: ProofInputUtxo::default(),
            change: ProofInputUtxo::default(),
            source_input_hash: [3; 32],
            external_data_hash: [4; 32],
            private_tx_blinding: [5; 32],
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
        expected.extend(expected_escrow_terms_witness_keys("Terms"));
        expected.extend(expected_utxo_witness_keys("EscrowUtxo"));
        expected.extend(expected_utxo_witness_keys("Change"));

        assert_eq!(keys, expected.into_iter().collect::<HashSet<String>>());
    }
}
