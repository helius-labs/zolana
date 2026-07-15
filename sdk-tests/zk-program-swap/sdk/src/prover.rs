use anyhow::Result;
use swap_prover::{
    CancelProofInputs, CreateProofInputs, FillProofInputs, FillVerifiableEncryptionProofInputs,
    OrderProof,
};

use crate::err;

#[derive(Default)]
pub struct SwapProverClient;

impl SwapProverClient {
    pub fn new() -> Self {
        Self
    }

    pub fn prove_create_swap(&self, inputs: &CreateProofInputs) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }

    pub fn prove_fill(&self, inputs: &FillProofInputs) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }

    pub fn prove_cancel(&self, inputs: &CancelProofInputs) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }

    pub fn prove_fill_verifiable_encryption(
        &self,
        inputs: &FillVerifiableEncryptionProofInputs,
    ) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }
}
