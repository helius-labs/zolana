use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use dynamic_swap_program::{
    circuits::{
        Commitment, EscrowCancel, EscrowOpen, PoolDeposit, PoolRebalance, PoolSettle, PoolWithdraw,
    },
    verifier::{
        escrow_cancel, escrow_open, pool_deposit, pool_rebalance, pool_settle, pool_withdraw,
    },
};
use once_cell::sync::OnceCell;
use spr_program::{
    checked,
    proof::{check_proving_key, compressed_proof},
    xark::{prover::Circuit, Input},
    CircuitError, ProgramProofInputs,
};

use crate::{err, Groth16ProofBytes};

type CachedCircuit = OnceCell<Circuit>;

static ESCROW_OPEN: CachedCircuit = OnceCell::new();
static POOL_SETTLE: CachedCircuit = OnceCell::new();
static ESCROW_CANCEL: CachedCircuit = OnceCell::new();
static POOL_DEPOSIT: CachedCircuit = OnceCell::new();
static POOL_WITHDRAW: CachedCircuit = OnceCell::new();
static POOL_REBALANCE: CachedCircuit = OnceCell::new();

/// `build-zk-program` writes each circuit, with its proving key, to
/// `target/zk/dynamic-swap-program/<circuit>`.
fn artifacts(circuit: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../target/zk/dynamic-swap-program")
        .join(circuit)
}

fn prove<P: Input>(
    program: &P,
    execute: impl FnOnce() -> Result<Commitment, CircuitError>,
    cache: &CachedCircuit,
    circuit: &str,
    checksum: &[u8; 32],
) -> Result<Groth16ProofBytes> {
    let commitment = checked(execute).map_err(err)?;
    let inputs = ProgramProofInputs::new(program, *commitment.public_hash());
    let directory = artifacts(circuit);
    let circuit = load_circuit(cache, &directory, checksum)?;
    let result = circuit.prove(inputs).map_err(err)?;
    let proof = compressed_proof(&result.proof).map_err(err)?;
    Ok(Groth16ProofBytes {
        proof_a: proof.a,
        proof_b: proof.b,
        proof_c: proof.c,
    })
}

/// The circuit in `directory`, parsed once. Its proving key is checked on
/// every call, because each proof reads the key from disk again.
fn load_circuit<'a>(
    cache: &'a CachedCircuit,
    directory: &Path,
    checksum: &[u8; 32],
) -> Result<&'a Circuit> {
    let loaded = (|| {
        let key = std::fs::read(directory.join("pk.bin"))?;
        check_proving_key(&key, checksum).map_err(err)?;
        cache.get_or_try_init(|| {
            if !directory.join("circuit.xbc").is_file() {
                bail!("the circuit is not built");
            }
            Ok(spr_program::xark::prover::circuit_at(directory))
        })
    })();
    loaded.with_context(|| {
        format!(
            "loading {}: run `just ensure-dynamic-swap-keys` to build matching keys",
            directory.display()
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
            || inputs.execute(),
            &ESCROW_OPEN,
            "escrow_open",
            &escrow_open::VERIFYINGKEY_PROVING_KEY_SHA256,
        )
    }

    pub fn prove_pool_settle(&self, inputs: &PoolSettle) -> Result<Groth16ProofBytes> {
        prove(
            inputs,
            || inputs.execute(),
            &POOL_SETTLE,
            "pool_settle",
            &pool_settle::VERIFYINGKEY_PROVING_KEY_SHA256,
        )
    }

    pub fn prove_escrow_cancel(&self, inputs: &EscrowCancel) -> Result<Groth16ProofBytes> {
        prove(
            inputs,
            || inputs.execute(),
            &ESCROW_CANCEL,
            "escrow_cancel",
            &escrow_cancel::VERIFYINGKEY_PROVING_KEY_SHA256,
        )
    }

    pub fn prove_pool_deposit(&self, inputs: &PoolDeposit) -> Result<Groth16ProofBytes> {
        prove(
            inputs,
            || inputs.execute(),
            &POOL_DEPOSIT,
            "pool_deposit",
            &pool_deposit::VERIFYINGKEY_PROVING_KEY_SHA256,
        )
    }

    pub fn prove_pool_withdraw(&self, inputs: &PoolWithdraw) -> Result<Groth16ProofBytes> {
        prove(
            inputs,
            || inputs.execute(),
            &POOL_WITHDRAW,
            "pool_withdraw",
            &pool_withdraw::VERIFYINGKEY_PROVING_KEY_SHA256,
        )
    }

    pub fn prove_pool_rebalance(&self, inputs: &PoolRebalance) -> Result<Groth16ProofBytes> {
        prove(
            inputs,
            || inputs.execute(),
            &POOL_REBALANCE,
            "pool_rebalance",
            &pool_rebalance::VERIFYINGKEY_PROVING_KEY_SHA256,
        )
    }
}
