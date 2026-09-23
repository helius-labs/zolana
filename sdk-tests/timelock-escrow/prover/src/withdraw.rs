use std::collections::HashMap;

use zolana_client::ProofInputUtxo;
use zolana_gnark_ffi_prover::{decimal, utxo_witness_entries, WitnessMap};

use crate::{CircuitId, EscrowTermsProofInput, TimelockProof, PROVER};

#[derive(Debug, Clone)]
pub struct WithdrawProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub terms: EscrowTermsProofInput,
    pub owner_pk_field: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub escrow_utxo: ProofInputUtxo,
    pub source_output: ProofInputUtxo,
    pub external_data_hash: [u8; 32],
    pub private_tx_blinding: [u8; 32],
}

impl WithdrawProofInputs {
    fn witness(&self) -> WitnessMap {
        let scalars: [(&str, [u8; 32]); 6] = [
            ("Public_PublicInputHash", self.public_input_hash),
            ("Public_PrivateTxHash", self.private_tx_hash),
            ("OwnerPkField", self.owner_pk_field),
            ("NullifierPk", self.nullifier_pk),
            ("ExternalDataHash", self.external_data_hash),
            ("PrivateTxBlinding", self.private_tx_blinding),
        ];
        let mut map = HashMap::new();
        for (key, value) in scalars.iter() {
            map.insert(key.to_string(), vec![decimal(value)]);
        }
        for (key, value) in self
            .terms
            .witness_entries("Terms")
            .into_iter()
            .chain(utxo_witness_entries(&self.escrow_utxo, "EscrowUtxo"))
            .chain(utxo_witness_entries(&self.source_output, "SourceOutput"))
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> zolana_gnark_ffi_prover::Result<TimelockProof> {
        Ok(PROVER
            .prove(CircuitId::Withdraw, &self.witness())?
            .compress()?
            .into())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use zolana_gnark_ffi_prover::expected_utxo_witness_keys;

    use super::*;
    use crate::escrow_terms::expected_escrow_terms_witness_keys;

    fn sample() -> WithdrawProofInputs {
        WithdrawProofInputs {
            public_input_hash: [1; 32],
            private_tx_hash: [2; 32],
            terms: EscrowTermsProofInput {
                owner_hash: [3; 32],
                unlock: 42,
            },
            owner_pk_field: [4; 32],
            nullifier_pk: [5; 32],
            escrow_utxo: ProofInputUtxo::default(),
            source_output: ProofInputUtxo::default(),
            external_data_hash: [6; 32],
            private_tx_blinding: [7; 32],
        }
    }

    #[test]
    fn witness_key_set_matches_circuit_fields() {
        let witness = sample().witness();
        let keys: HashSet<String> = witness.keys().cloned().collect();

        let mut expected: Vec<String> = vec![
            "Public_PublicInputHash".to_string(),
            "Public_PrivateTxHash".to_string(),
            "OwnerPkField".to_string(),
            "NullifierPk".to_string(),
            "ExternalDataHash".to_string(),
            "PrivateTxBlinding".to_string(),
        ];
        expected.extend(expected_escrow_terms_witness_keys("Terms"));
        expected.extend(expected_utxo_witness_keys("EscrowUtxo"));
        expected.extend(expected_utxo_witness_keys("SourceOutput"));

        assert_eq!(keys, expected.into_iter().collect::<HashSet<String>>());
    }
}
