use anyhow::Result;
use dynamic_swap_prover::{
    EscrowOpenProofInputs, EscrowRefundProofInputs, EscrowSettleProofInputs, OrderProof,
    PoolUpdateProofInputs,
};

fn err(e: impl core::fmt::Debug) -> anyhow::Error {
    anyhow::anyhow!("{e:?}")
}

#[derive(Default)]
pub struct DynamicSwapProverClient;

impl DynamicSwapProverClient {
    pub fn new() -> Self {
        Self
    }

    pub fn prove_pool_update(&self, inputs: &PoolUpdateProofInputs) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }

    pub fn prove_escrow_open(&self, inputs: &EscrowOpenProofInputs) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }

    pub fn prove_escrow_settle(&self, inputs: &EscrowSettleProofInputs) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }

    pub fn prove_escrow_refund(&self, inputs: &EscrowRefundProofInputs) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }
}
