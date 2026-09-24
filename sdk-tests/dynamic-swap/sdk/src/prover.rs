use anyhow::Result;
use dynamic_swap_prover::{
    EscrowCancelProofInputs, EscrowOpenProofInputs, OrderProof, PoolRebalanceProofInputs,
    PoolSettleProofInputs, PoolWithdrawProofInputs,
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

    pub fn prove_escrow_open(&self, inputs: &EscrowOpenProofInputs) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }

    pub fn prove_pool_settle(&self, inputs: &PoolSettleProofInputs) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }

    pub fn prove_escrow_cancel(&self, inputs: &EscrowCancelProofInputs) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }

    pub fn prove_pool_withdraw(&self, inputs: &PoolWithdrawProofInputs) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }

    pub fn prove_pool_rebalance(&self, inputs: &PoolRebalanceProofInputs) -> Result<OrderProof> {
        inputs.prove().map_err(err)
    }
}
