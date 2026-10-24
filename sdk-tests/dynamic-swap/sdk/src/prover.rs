use std::path::Path;

use anyhow::{Context, Result};
use dynamic_swap_program::{
    circuits::{EscrowCancel, EscrowOpen, PoolDeposit, PoolRebalance, PoolSettle, PoolWithdraw},
    verifier::{
        escrow_cancel, escrow_open, pool_deposit, pool_rebalance, pool_settle, pool_withdraw,
    },
};
use once_cell::sync::OnceCell;
use zolana_program::{CompressedProof, Groth16Keys, Groth16Prover, ZkCircuit};

use crate::{err, Groth16ProofBytes};

type CachedProver<C> = OnceCell<Groth16Prover<C>>;

static ESCROW_OPEN: CachedProver<EscrowOpen> = OnceCell::new();
static POOL_SETTLE: CachedProver<PoolSettle> = OnceCell::new();
static ESCROW_CANCEL: CachedProver<EscrowCancel> = OnceCell::new();
static POOL_DEPOSIT: CachedProver<PoolDeposit> = OnceCell::new();
static POOL_WITHDRAW: CachedProver<PoolWithdraw> = OnceCell::new();
static POOL_REBALANCE: CachedProver<PoolRebalance> = OnceCell::new();

fn prove<C: ZkCircuit + 'static>(
    inputs: &C,
    cache: &CachedProver<C>,
    circuit: &str,
    checksum: &[u8; 32],
) -> Result<Groth16ProofBytes> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../target/zk/dynamic-swap-program")
        .join(format!("{circuit}.pk"));
    let prover = load_prover(cache, &path, checksum)?;
    let result = prover.prove(inputs).map_err(err)?;
    let proof = CompressedProof::try_from(&result.proof).map_err(err)?;
    Ok(Groth16ProofBytes {
        proof_a: proof.a,
        proof_b: proof.b,
        proof_c: proof.c,
    })
}

fn load_prover<'a, C: ZkCircuit + 'static>(
    cache: &'a CachedProver<C>,
    path: &Path,
    checksum: &[u8; 32],
) -> Result<&'a Groth16Prover<C>> {
    cache
        .get_or_try_init(|| {
            let keys = Groth16Keys::load_checked(path, checksum).map_err(err)?;
            Groth16Prover::<C>::new(keys).map_err(err)
        })
        .with_context(|| {
            format!(
                "loading {}: run `just ensure-dynamic-swap-keys` to build matching keys",
                path.display()
            )
        })
}

#[cfg(test)]
#[path = "prover_test.rs"]
mod tests;

#[derive(Default)]
pub struct DynamicSwapProverClient;

impl DynamicSwapProverClient {
    pub fn new() -> Self {
        Self
    }

    pub fn prove_escrow_open(&self, inputs: &EscrowOpen) -> Result<Groth16ProofBytes> {
        prove(
            inputs,
            &ESCROW_OPEN,
            "escrow_open",
            &escrow_open::VERIFYINGKEY_PROVING_KEY_SHA256,
        )
    }

    pub fn prove_pool_settle(&self, inputs: &PoolSettle) -> Result<Groth16ProofBytes> {
        prove(
            inputs,
            &POOL_SETTLE,
            "pool_settle",
            &pool_settle::VERIFYINGKEY_PROVING_KEY_SHA256,
        )
    }

    pub fn prove_escrow_cancel(&self, inputs: &EscrowCancel) -> Result<Groth16ProofBytes> {
        prove(
            inputs,
            &ESCROW_CANCEL,
            "escrow_cancel",
            &escrow_cancel::VERIFYINGKEY_PROVING_KEY_SHA256,
        )
    }

    pub fn prove_pool_deposit(&self, inputs: &PoolDeposit) -> Result<Groth16ProofBytes> {
        prove(
            inputs,
            &POOL_DEPOSIT,
            "pool_deposit",
            &pool_deposit::VERIFYINGKEY_PROVING_KEY_SHA256,
        )
    }

    pub fn prove_pool_withdraw(&self, inputs: &PoolWithdraw) -> Result<Groth16ProofBytes> {
        prove(
            inputs,
            &POOL_WITHDRAW,
            "pool_withdraw",
            &pool_withdraw::VERIFYINGKEY_PROVING_KEY_SHA256,
        )
    }

    pub fn prove_pool_rebalance(&self, inputs: &PoolRebalance) -> Result<Groth16ProofBytes> {
        prove(
            inputs,
            &POOL_REBALANCE,
            "pool_rebalance",
            &pool_rebalance::VERIFYINGKEY_PROVING_KEY_SHA256,
        )
    }
}
