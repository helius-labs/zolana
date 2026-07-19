use anyhow::Result;
use timelock_escrow_prover::{EscrowProofInputs, TimelockProof, WithdrawProofInputs};

use crate::err;

#[derive(Default)]
pub struct EscrowProverClient;

impl EscrowProverClient {
    pub fn new() -> Self {
        Self
    }

    pub fn prove_escrow(&self, inputs: &EscrowProofInputs) -> Result<TimelockProof> {
        inputs.prove().map_err(err)
    }

    pub fn prove_withdraw(&self, inputs: &WithdrawProofInputs) -> Result<TimelockProof> {
        inputs.prove().map_err(err)
    }
}
