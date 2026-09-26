use crate::proof_inputs::{ProofInputWriter, ProofInputs};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscrowTermsProofInput {
    pub owner_hash: [u8; 32],
    pub unlock: u64,
}

impl ProofInputs for EscrowTermsProofInput {
    fn write(&self, writer: &mut ProofInputWriter<'_>) {
        writer.field("OwnerHash", &self.owner_hash);
        writer.u64("Unlock", self.unlock);
    }
}

#[cfg(test)]
pub(crate) fn expected_escrow_terms_keys(prefix: &str) -> Vec<String> {
    ["OwnerHash", "Unlock"]
        .iter()
        .map(|suffix| format!("{prefix}_{suffix}"))
        .collect()
}
