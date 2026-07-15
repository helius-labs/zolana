use anyhow::Result;
use swap_prover::{
    CancelProofInputs, MakeProofInputs, OrderProof, TakeProofInputs,
    TakeVerifiableEncryptionProofInputs,
};

use crate::err;

#[derive(Default)]
pub struct SwapProverClient;

impl SwapProverClient {
    pub fn new() -> Self {
        Self
    }

    pub fn prove_make(&self, inputs: &MakeProofInputs) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }

    pub fn prove_take(&self, inputs: &TakeProofInputs) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }

    pub fn prove_cancel(&self, inputs: &CancelProofInputs) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }

    pub fn prove_take_verifiable_encryption(
        &self,
        inputs: &TakeVerifiableEncryptionProofInputs,
    ) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }
}
