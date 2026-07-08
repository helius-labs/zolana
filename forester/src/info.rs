//! Read-only SPP status report.
//!
//! Fetches the pool tree account, nullifier queue batches, and the forester's
//! balance over RPC and renders a summary. It never proves or submits a
//! transaction; use it to decide whether the worker has work. The default is a
//! human-readable report; `--json` emits a stable machine-readable object for
//! monitoring / gating a run (e.g.
//! `forester info --json | jq '.nullifier_queue.ready_to_forest_zkp_batches'`).

use std::env;

use anyhow::{anyhow, Context, Result};
use serde_json::json;
use solana_commitment_config::CommitmentConfig;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signer::Signer;
use zolana_batched_merkle_tree::batch::BatchState;
use zolana_tree::TreeAccount;

const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

/// One nullifier queue batch, gathered once so the human and JSON renderers
/// report identical numbers.
struct BatchInfo {
    index: usize,
    state: &'static str,
    queued: u64,
    ready_zkps: u64,
    inserted_zkps: u64,
    zkp_batch_index: u64,
    num_zkp_batches: u64,
}

/// Print the current state of `tree`, its nullifier queue, and the forester
/// balance. Reads `RPC_URL`, `PAYER`, and `PROVER_URL` from the environment.
pub fn run(tree: Pubkey, json_output: bool) -> Result<()> {
    let rpc_url = env::var("RPC_URL").context("RPC_URL is not set")?;
    let rpc = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let mut data = rpc
        .get_account_with_commitment(&tree, CommitmentConfig::confirmed())
        .map_err(|err| anyhow!("fetch tree account {tree}: {err}"))?
        .value
        .ok_or_else(|| anyhow!("tree account not found: {tree}"))?
        .data;

    let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes())
        .map_err(|err| anyhow!("parse tree account {tree}: {err:?}"))?;

    // --- state (UTXO) tree: synchronous SMT, no queue ---
    let (leaves, height, root_index) = {
        let utxo = account.utxo_tree();
        (utxo.next_index(), utxo.height(), utxo.current_root_index())
    };
    let state_root = account
        .get_utxo_tree_root(root_index)
        .map_err(|err| anyhow!("read state root at index {root_index}: {err:?}"))?;

    // --- nullifier tree: batched queue the forester drains ---
    let (
        zkp_batch_size,
        batch_size,
        num_batches,
        batch_infos,
        ready_total,
        pending_batch_index,
        currently_processing_batch_index,
        nullifier_root,
    ) = {
        let nullifier_tree = account.nullifer_tree();
        let metadata = *nullifier_tree.get_metadata();
        let batches = &metadata.queue_batches;
        let mut infos = Vec::with_capacity(batches.batches.len());
        let mut ready_total = 0u64;
        for (index, batch) in batches.batches.iter().enumerate() {
            let ready = batch.get_num_ready_zkp_updates();
            ready_total += ready;
            infos.push(BatchInfo {
                index,
                state: batch.try_get_state().map(state_name).unwrap_or("unknown"),
                queued: batch.get_num_inserted_elements(),
                ready_zkps: ready,
                inserted_zkps: batch.get_num_inserted_zkps(),
                zkp_batch_index: batch.get_current_zkp_batch_index(),
                num_zkp_batches: batch.get_num_zkp_batches(),
            });
        }
        (
            batches.zkp_batch_size,
            batches.batch_size,
            batches.num_batches,
            infos,
            ready_total,
            batches.pending_batch_index,
            batches.currently_processing_batch_index,
            nullifier_tree.get_root(),
        )
    };
    // Approximate: each ready zkp-batch holds a full zkp_batch_size of nullifiers.
    let ready_nullifiers = ready_total.saturating_mul(zkp_batch_size);

    // --- forester balance (fee capacity); None when PAYER is unset ---
    let forester = read_forester(&rpc)?;
    let prover_url = env::var("PROVER_URL").ok();

    if json_output {
        let value = json!({
            "tree": tree.to_string(),
            "state_tree": {
                "height": height,
                "leaves": leaves,
                "root": hex::encode(state_root),
            },
            "nullifier_queue": {
                "zkp_batch_size": zkp_batch_size,
                "batch_size": batch_size,
                "num_batches": num_batches,
                "batches": batch_infos
                    .iter()
                    .map(|batch| json!({
                        "index": batch.index,
                        "state": batch.state,
                        "queued": batch.queued,
                        "ready_zkps": batch.ready_zkps,
                        "inserted_zkps": batch.inserted_zkps,
                        "zkp_batch_index": batch.zkp_batch_index,
                        "num_zkp_batches": batch.num_zkp_batches,
                    }))
                    .collect::<Vec<_>>(),
                "ready_to_forest_zkp_batches": ready_total,
                "ready_to_forest_nullifiers_approx": ready_nullifiers,
                "pending_batch_index": pending_batch_index,
                "currently_processing_batch_index": currently_processing_batch_index,
                "root": nullifier_root.map(hex::encode),
            },
            "forester": forester.as_ref().map(|(pubkey, lamports)| json!({
                "pubkey": pubkey.to_string(),
                "balance_lamports": lamports,
                "balance_sol": lamports_to_sol(*lamports),
            })),
            "prover_url": prover_url,
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }

    println!("tree {tree} (state height {height}, {leaves} leaves)");
    println!("  state root: {}", hex::encode(state_root));
    println!("nullifier queue (batched):");
    println!("  zkp_batch_size={zkp_batch_size}  batch_size={batch_size}  batches={num_batches}");
    for batch in &batch_infos {
        println!(
            "  batch {}: state={:<8} queued={}  ready_zkps={}  inserted_zkps={}  \
             zkp_batch_index={}  num_zkp_batches={}",
            batch.index,
            batch.state,
            batch.queued,
            batch.ready_zkps,
            batch.inserted_zkps,
            batch.zkp_batch_index,
            batch.num_zkp_batches,
        );
    }
    println!("  => READY TO FOREST: {ready_total} zkp-batches (~{ready_nullifiers} nullifiers)");
    println!(
        "  pending_batch_index={pending_batch_index}  \
         currently_processing_batch_index={currently_processing_batch_index}"
    );
    match nullifier_root {
        Some(root) => println!("  nullifier root: {}", hex::encode(root)),
        None => println!("  nullifier root: <none>"),
    }
    match &forester {
        Some((pubkey, lamports)) => println!(
            "forester {pubkey}: {} SOL   (fee capacity)",
            lamports_to_sol(*lamports)
        ),
        None => println!("forester key: unset (set PAYER)"),
    }
    println!("prover: {}", prover_url.as_deref().unwrap_or("unset"));
    Ok(())
}

/// Resolve the forester keypair from `PAYER` and fetch its balance. `Ok(None)`
/// when `PAYER` is unset (info still succeeds); errors only when `PAYER` is set
/// but malformed or the balance RPC fails.
fn read_forester(rpc: &RpcClient) -> Result<Option<(Pubkey, u64)>> {
    let payer = match env::var("PAYER") {
        Ok(payer) => payer,
        Err(_) => return Ok(None),
    };
    let keypair = crate::parse_payer_keypair(&payer)?;
    let pubkey = keypair.pubkey();
    let lamports = rpc
        .get_balance(&pubkey)
        .map_err(|err| anyhow!("fetch balance for {pubkey}: {err}"))?;
    Ok(Some((pubkey, lamports)))
}

fn state_name(state: BatchState) -> &'static str {
    match state {
        BatchState::Fill => "Fill",
        BatchState::Full => "Full",
        BatchState::Inserted => "Inserted",
    }
}

fn lamports_to_sol(lamports: u64) -> String {
    format!(
        "{}.{:09}",
        lamports / LAMPORTS_PER_SOL,
        lamports % LAMPORTS_PER_SOL
    )
}
