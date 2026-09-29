use zolana_client::ProofInputUtxo;

use crate::proof_inputs::{ProofInputWriter, ProofInputs};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionProofInputs {
    pub external_data_hash: [u8; 32],
    pub first_nullifier: [u8; 32],
    pub blinding_seed: [u8; 32],
    pub output_tree_id: u16,
}

impl ProofInputs for TransactionProofInputs {
    fn write(&self, writer: &mut ProofInputWriter<'_>) {
        writer.field("ExternalDataHash", &self.external_data_hash);
        writer.field("FirstNullifier", &self.first_nullifier);
        writer.field("BlindingSeed", &self.blinding_seed);
        writer.u64("OutputTreeID", u64::from(self.output_tree_id));
    }
}

#[derive(Debug, Clone)]
pub struct ProgramUtxoProofInputs<S> {
    pub utxo: ProofInputUtxo,
    pub state: S,
}

impl<S: ProofInputs> ProofInputs for ProgramUtxoProofInputs<S> {
    fn write(&self, writer: &mut ProofInputWriter<'_>) {
        writer.nested("Utxo", &self.utxo);
        writer.nested("State", &self.state);
    }
}
