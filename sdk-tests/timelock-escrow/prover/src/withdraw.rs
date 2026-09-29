use crate::{
    proof_inputs::{proof_input_map, ProofInputWriter, ProofInputs},
    zk_program::{ProgramUtxoProofInputs, TransactionProofInputs},
    CircuitId, EscrowTermsProofInput, TimelockProof, PROVER,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithdrawPublicProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
}

impl ProofInputs for WithdrawPublicProofInputs {
    fn write(&self, writer: &mut ProofInputWriter<'_>) {
        writer.field("PublicInputHash", &self.public_input_hash);
        writer.field("PrivateTxHash", &self.private_tx_hash);
    }
}

#[derive(Debug, Clone)]
pub struct WithdrawProofInputs {
    pub public: WithdrawPublicProofInputs,
    pub tx: TransactionProofInputs,
    pub escrow_utxo: ProgramUtxoProofInputs<EscrowTermsProofInput>,
    pub owner_pk_field: [u8; 32],
    pub nullifier_pk: [u8; 32],
}

impl ProofInputs for WithdrawProofInputs {
    fn write(&self, writer: &mut ProofInputWriter<'_>) {
        writer.nested("Public", &self.public);
        writer.nested("Tx", &self.tx);
        writer.nested("EscrowUtxo", &self.escrow_utxo);
        writer.field("OwnerPkField", &self.owner_pk_field);
        writer.field("NullifierPk", &self.nullifier_pk);
    }
}

impl WithdrawProofInputs {
    pub fn prove(&self) -> zolana_gnark_ffi_prover::Result<TimelockProof> {
        Ok(PROVER
            .prove(CircuitId::Withdraw, &proof_input_map(self))?
            .compress()?
            .into())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use zolana_client::ProofInputUtxo;
    use zolana_gnark_ffi_prover::utxo_proof_input_keys;

    use super::*;
    use crate::escrow_terms::expected_escrow_terms_keys;

    #[test]
    fn proof_input_keys_match_circuit_fields() {
        let inputs = WithdrawProofInputs {
            public: WithdrawPublicProofInputs {
                public_input_hash: [1; 32],
                private_tx_hash: [2; 32],
            },
            tx: TransactionProofInputs {
                external_data_hash: [3; 32],
                first_nullifier: [4; 32],
                blinding_seed: [5; 32],
                output_tree_id: 6,
            },
            escrow_utxo: ProgramUtxoProofInputs {
                utxo: ProofInputUtxo::default(),
                state: EscrowTermsProofInput {
                    owner_hash: [7; 32],
                    unlock: 42,
                },
            },
            owner_pk_field: [8; 32],
            nullifier_pk: [9; 32],
        };
        let keys: BTreeSet<String> = proof_input_map(&inputs).keys().cloned().collect();

        let mut expected: BTreeSet<String> = [
            "Public_PublicInputHash".to_string(),
            "Public_PrivateTxHash".to_string(),
            "Tx_ExternalDataHash".to_string(),
            "Tx_FirstNullifier".to_string(),
            "Tx_BlindingSeed".to_string(),
            "Tx_OutputTreeID".to_string(),
            "OwnerPkField".to_string(),
            "NullifierPk".to_string(),
        ]
        .into();
        expected.extend(utxo_proof_input_keys("EscrowUtxo_Utxo"));
        expected.extend(expected_escrow_terms_keys("EscrowUtxo_State"));

        assert_eq!(keys, expected);
    }
}
