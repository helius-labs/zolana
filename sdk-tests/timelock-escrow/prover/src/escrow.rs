use crate::{
    proof_inputs::{proof_input_map, ProofInputWriter, ProofInputs},
    zk_program::{ProgramUtxoProofInputs, TransactionProofInputs},
    CircuitId, EscrowTermsProofInput, FundingProofInput, TimelockProof, PROVER,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscrowPublicProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub escrow_owner_hash: [u8; 32],
}

impl ProofInputs for EscrowPublicProofInputs {
    fn write(&self, writer: &mut ProofInputWriter<'_>) {
        writer.field("PublicInputHash", &self.public_input_hash);
        writer.field("PrivateTxHash", &self.private_tx_hash);
        writer.field("EscrowOwnerHash", &self.escrow_owner_hash);
    }
}

#[derive(Debug, Clone)]
pub struct EscrowProofInputs {
    pub public: EscrowPublicProofInputs,
    pub tx: TransactionProofInputs,
    pub source: ProgramUtxoProofInputs<FundingProofInput>,
    pub terms: EscrowTermsProofInput,
    pub amount: u64,
}

impl ProofInputs for EscrowProofInputs {
    fn write(&self, writer: &mut ProofInputWriter<'_>) {
        writer.nested("Public", &self.public);
        writer.nested("Tx", &self.tx);
        writer.nested("Source", &self.source);
        writer.nested("Terms", &self.terms);
        writer.u64("Amount", self.amount);
    }
}

impl EscrowProofInputs {
    pub fn prove(&self) -> zolana_gnark_ffi_prover::Result<TimelockProof> {
        Ok(PROVER
            .prove(CircuitId::Escrow, &proof_input_map(self))?
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
        let inputs = EscrowProofInputs {
            public: EscrowPublicProofInputs {
                public_input_hash: [1; 32],
                private_tx_hash: [2; 32],
                escrow_owner_hash: [3; 32],
            },
            tx: TransactionProofInputs {
                external_data_hash: [4; 32],
                first_nullifier: [5; 32],
                blinding_seed: [6; 32],
                output_tree_id: 7,
            },
            source: ProgramUtxoProofInputs {
                utxo: ProofInputUtxo::default(),
                state: FundingProofInput {
                    owner_hash: [10; 32],
                },
            },
            terms: EscrowTermsProofInput {
                owner_hash: [8; 32],
                unlock: 42,
            },
            amount: 9,
        };
        let keys: BTreeSet<String> = proof_input_map(&inputs).keys().cloned().collect();

        let mut expected: BTreeSet<String> = [
            "Public_PublicInputHash".to_string(),
            "Public_PrivateTxHash".to_string(),
            "Public_EscrowOwnerHash".to_string(),
            "Tx_ExternalDataHash".to_string(),
            "Tx_FirstNullifier".to_string(),
            "Tx_BlindingSeed".to_string(),
            "Tx_OutputTreeID".to_string(),
            "Amount".to_string(),
        ]
        .into();
        expected.extend(utxo_proof_input_keys("Source_Utxo"));
        expected.insert("Source_State_OwnerHash".to_string());
        expected.extend(expected_escrow_terms_keys("Terms"));

        assert_eq!(keys, expected);
    }
}
