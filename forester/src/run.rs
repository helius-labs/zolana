//! `forester run`: prove and submit ready nullifier-tree zkp-batches.
//!
//! The nullifier tree is a batched indexed Merkle tree: transfers queue
//! nullifiers, and the forester periodically appends a full zkp-batch of them
//! into the tree via `batch_update_nullifier_tree`, advancing the root. Proving
//! an append needs low-/new-element non-membership proofs against the tree
//! state *before* that batch, which the on-chain account does not retain.
//!
//! We rebuild that state the same way
//! `program-libs/batched-merkle-tree/tests/nullifier_tree.rs` does: replay the
//! ordered queued nullifier values (served by photon) into an in-memory
//! reference `IndexedMerkleTree`, verify the reconstructed root matches the
//! on-chain root, then build each ready zkp-batch's witness, prove it on the
//! forester prover, and submit the updates in root order. Each on-chain update
//! checks `old_root == current root`, so submission is strictly sequential;
//! proving could be parallelised (see PR #89) as a follow-up.

use std::{env, fmt, thread, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use num_bigint::BigUint;
use num_traits::Num;
use solana_commitment_config::CommitmentConfig;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use zolana_client::{BatchAddressAppendInputs, ProofCompressed, ProverClient};
use zolana_hasher::{hash_chain::create_hash_chain_from_array, Poseidon};
use zolana_interface::instruction::{BatchUpdateNullifierTreeData, CompressedProof};
use zolana_merkle_tree::indexed::IndexedMerkleTree;
use zolana_tree::TreeAccount;

type ReferenceNullifierTree = IndexedMerkleTree<Poseidon, usize>;

use crate::forest::{batch_update_nullifier_tree_once, ForestParams};
use zolana_api::{types::SerializablePubkey, BlockingZolanaApi};

/// BN254 scalar field modulus minus one: the nullifier tree's initial
/// `next_value` sentinel. Pinned by `reference_tree_matches_on_chain_init`
/// against `NULLIFIER_TREE_INIT_ROOT_40`. (The address tree uses
/// `HIGHEST_ADDRESS_PLUS_ONE` via `IndexedMerkleTree::new`; the nullifier tree
/// does not — it ranges over the full field.)
const NULLIFIER_INIT_NEXT_VALUE_DEC: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495616";

/// Options for a `forester run` invocation.
pub struct RunOptions {
    /// Pool tree whose nullifier queue to drain.
    pub tree: Pubkey,
    /// Forester smart-account settings; the vault at `account_index` is the
    /// tree's `forester_authority`. Required to submit (not for `--dry-run`).
    pub settings: Option<Pubkey>,
    /// Vault index within the settings (default 0).
    pub account_index: u8,
    /// Cap on zkp-batches submitted across the whole invocation (all ready when
    /// `None`).
    pub max_batches: Option<u64>,
    /// Keep polling for newly-ready batches after draining instead of exiting.
    pub watch: bool,
    /// Seconds between polls in `--watch` mode.
    pub poll_secs: u64,
    /// Preflight only: read the tree, fetch queued values from photon,
    /// reconstruct the reference tree, verify the reconstructed root matches
    /// on-chain, and report — without proving or submitting.
    pub dry_run: bool,
}

/// Read-once view of the nullifier tree's batch state.
struct TreeSnapshot {
    next_index: u64,
    height: u32,
    zkp_batch_size: u64,
    already_applied: u64,
    ready: u64,
    pending_queued: u64,
    on_chain_root: [u8; 32],
    /// Leaves hash chain per ready zkp-batch, in order.
    hash_chains: Vec<[u8; 32]>,
}

#[derive(Debug, PartialEq, Eq)]
struct PhotonIndexNotReady {
    returned: usize,
    needed: u64,
    detail: String,
}

impl PhotonIndexNotReady {
    fn new(returned: usize, needed: u64, detail: impl Into<String>) -> Self {
        Self {
            returned,
            needed,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for PhotonIndexNotReady {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "photon returned {} queued nullifiers, need at least {} ({})",
            self.returned, self.needed, self.detail
        )
    }
}

impl std::error::Error for PhotonIndexNotReady {}

enum DrainOutcome {
    Drained(u64),
    NotReady(PhotonIndexNotReady),
}

fn indexed_value_shortage(
    returned: usize,
    needed: u64,
    detail: impl Into<String>,
) -> Option<PhotonIndexNotReady> {
    match u64::try_from(returned) {
        Ok(returned) if returned >= needed => None,
        _ => Some(PhotonIndexNotReady::new(returned, needed, detail)),
    }
}

/// Drain ready nullifier zkp-batches for `opts.tree`. Reads `RPC_URL`,
/// `PROVER_URL`, `PHOTON_URL`, and `PAYER` (forester keypair) from the
/// environment. Must run on a thread with no Tokio runtime — the prover and
/// photon clients use `reqwest::blocking`.
pub fn run(opts: RunOptions) -> Result<()> {
    let rpc_url = env::var("RPC_URL").context("RPC_URL is not set")?;
    let photon_url = env::var("PHOTON_URL").context("PHOTON_URL is not set")?;
    let photon = BlockingZolanaApi::new(photon_url);

    if opts.dry_run {
        return check_once(&rpc_url, &photon, opts.tree);
    }

    let prover_url = env::var("PROVER_URL").context("PROVER_URL is not set")?;
    let settings = opts
        .settings
        .ok_or_else(|| anyhow!("--settings (forester smart-account) is required to submit"))?;
    let member = forester_keypair()?;
    let prover = ProverClient::new(prover_url);

    tracing::info!(tree = %opts.tree, "forester run: draining nullifier queue");

    let mut submitted_total: u64 = 0;
    loop {
        let remaining = opts
            .max_batches
            .map(|max| max.saturating_sub(submitted_total));
        if matches!(remaining, Some(0)) {
            tracing::info!(submitted_total, "reached --max-batches cap");
            break;
        }

        let outcome = drain_once(
            &rpc_url,
            &prover,
            &photon,
            &member,
            settings,
            opts.account_index,
            opts.tree,
            remaining,
        )?;
        let submitted = match outcome {
            DrainOutcome::Drained(submitted) => submitted,
            DrainOutcome::NotReady(not_ready) => {
                if opts.watch {
                    tracing::warn!(
                        %not_ready,
                        poll_secs = opts.poll_secs,
                        "photon has not indexed enough nullifier queue elements; retrying"
                    );
                    thread::sleep(Duration::from_secs(opts.poll_secs));
                    continue;
                }
                bail!("{not_ready}");
            }
        };
        submitted_total += submitted;

        if !opts.watch {
            break;
        }
        if submitted == 0 {
            thread::sleep(Duration::from_secs(opts.poll_secs));
        }
    }

    tracing::info!(submitted_total, "forester run complete");
    Ok(())
}

/// Read the nullifier tree's batch state and the ready zkp-batches' hash chains.
fn read_snapshot(rpc_url: &str, tree: Pubkey) -> Result<TreeSnapshot> {
    let rpc = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
    let mut data = rpc
        .get_account_with_commitment(&tree, CommitmentConfig::confirmed())
        .map_err(|err| anyhow!("fetch tree account {tree}: {err}"))?
        .value
        .ok_or_else(|| anyhow!("tree account not found: {tree}"))?
        .data;

    let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes())
        .map_err(|err| anyhow!("parse tree account {tree}: {err:?}"))?;
    let nullifier = account.nullifer_tree();
    let metadata = *nullifier.get_metadata();
    let on_chain_root = nullifier
        .get_root()
        .ok_or_else(|| anyhow!("nullifier tree has no root"))?;

    let pending = metadata.queue_batches.pending_batch_index as usize;
    let zkp_batch_size = metadata.queue_batches.zkp_batch_size;
    let batch = *metadata
        .queue_batches
        .batches
        .get(pending)
        .ok_or_else(|| anyhow!("pending_batch_index {pending} out of range"))?;
    let already_applied = batch.get_num_inserted_zkps();
    let ready = batch.get_num_ready_zkp_updates();
    let pending_queued = batch.get_num_inserted_elements();

    let mut hash_chains = Vec::with_capacity(ready as usize);
    for i in 0..ready {
        let zkp_index = (already_applied + i) as usize;
        let hash_chain = nullifier
            .get_hash_chain(pending, zkp_index)
            .ok_or_else(|| {
                anyhow!("missing leaves hash chain for batch {pending} zkp {zkp_index}")
            })?;
        hash_chains.push(hash_chain);
    }

    Ok(TreeSnapshot {
        next_index: metadata.next_index,
        height: metadata.height,
        zkp_batch_size,
        already_applied,
        ready,
        pending_queued,
        on_chain_root,
        hash_chains,
    })
}

/// Nullifiers already appended into the tree; the init element occupies leaf 0.
fn applied_count(snapshot: &TreeSnapshot) -> Result<u64> {
    snapshot
        .next_index
        .checked_sub(1)
        .ok_or_else(|| anyhow!("nullifier tree next_index is 0 (uninitialized)"))
}

/// Fetch queued values from photon, replay the already-appended prefix into a
/// fresh reference tree, and verify the reconstructed root matches on-chain.
/// Returns the reference tree (at the on-chain state) and the fetched values.
fn reconstruct_and_verify(
    photon: &BlockingZolanaApi,
    tree: Pubkey,
    snapshot: &TreeSnapshot,
    fetch_total: u64,
) -> Result<(ReferenceNullifierTree, Vec<[u8; 32]>)> {
    let applied = applied_count(snapshot)?;
    let tree_account = SerializablePubkey(bs58::encode(tree.to_bytes()).into_string());
    let elements = photon
        .get_nullifier_queue_elements(tree_account, Some(0), fetch_total)
        .map_err(|err| anyhow!("fetch queued nullifiers from photon: {err}"))?
        .elements;
    if let Some(not_ready) = indexed_value_shortage(
        elements.len(),
        applied,
        format!("the {applied} already-applied nullifiers required to reconstruct"),
    ) {
        return Err(not_ready.into());
    }
    let mut values = Vec::with_capacity(elements.len());
    for (index, element) in elements.into_iter().enumerate() {
        if element.seq != index as u64 {
            bail!(
                "queued nullifier sequence gap at index {index}: photon returned seq {}",
                element.seq
            );
        }
        let decoded = bs58::decode(&element.value.0)
            .into_vec()
            .map_err(|err| anyhow!("decode nullifier {}: {err}", element.value.0))?;
        let value: [u8; 32] = decoded.try_into().map_err(|bytes: Vec<u8>| {
            anyhow!("nullifier decoded to {} bytes, expected 32", bytes.len())
        })?;
        values.push(value);
    }

    let applied_len = usize::try_from(applied)
        .map_err(|_| anyhow!("applied nullifier count {applied} exceeds usize"))?;
    let applied_values = values
        .get(..applied_len)
        .ok_or_else(|| anyhow!("queued nullifier prefix length {applied_len} out of range"))?;

    let mut reference = reference_nullifier_tree(snapshot.height)?;
    for value in applied_values {
        reference
            .append(&BigUint::from_bytes_be(value))
            .map_err(|err| anyhow!("replay appended nullifier: {err:?}"))?;
    }
    if reference.root() != snapshot.on_chain_root {
        bail!(
            "reconstructed nullifier root {} does not match on-chain root {}; refusing to proceed",
            hex::encode(reference.root()),
            hex::encode(snapshot.on_chain_root)
        );
    }
    Ok((reference, values))
}

/// One drain pass: prove+submit the pending batch's ready zkp-batches (capped by
/// `limit`). Returns how many were submitted.
#[allow(clippy::too_many_arguments)]
fn drain_once(
    rpc_url: &str,
    prover: &ProverClient,
    photon: &BlockingZolanaApi,
    member: &Keypair,
    settings: Pubkey,
    account_index: u8,
    tree: Pubkey,
    limit: Option<u64>,
) -> Result<DrainOutcome> {
    let snapshot = read_snapshot(rpc_url, tree)?;
    if snapshot.ready == 0 {
        tracing::info!("no ready zkp-batches to forest");
        return Ok(DrainOutcome::Drained(0));
    }
    tracing::info!(
        ready = snapshot.ready,
        zkp_batch_size = snapshot.zkp_batch_size,
        "ready zkp-batches"
    );

    let applied = applied_count(&snapshot)?;
    let needed = applied + snapshot.ready * snapshot.zkp_batch_size;
    let (mut reference, values) = match reconstruct_and_verify(photon, tree, &snapshot, needed) {
        Ok(reconstructed) => reconstructed,
        Err(err) => {
            let not_ready = err.downcast::<PhotonIndexNotReady>()?;
            return Ok(DrainOutcome::NotReady(not_ready));
        }
    };
    if let Some(not_ready) = indexed_value_shortage(
        values.len(),
        needed,
        format!("applied {applied} + {} ready zkp-batch(es)", snapshot.ready),
    ) {
        return Ok(DrainOutcome::NotReady(not_ready));
    }

    let cap = limit
        .map(|limit| limit.min(snapshot.ready))
        .unwrap_or(snapshot.ready);
    let mut submitted = 0u64;
    for i in 0..cap {
        let zkp_index = snapshot.already_applied + i;
        let batch_next_index = snapshot.next_index + i * snapshot.zkp_batch_size;
        let start = usize::try_from(applied + i * snapshot.zkp_batch_size)
            .map_err(|_| anyhow!("zkp-batch {zkp_index} start exceeds usize"))?;
        let end =
            start
                .checked_add(usize::try_from(snapshot.zkp_batch_size).map_err(|_| {
                    anyhow!("zkp_batch_size {} exceeds usize", snapshot.zkp_batch_size)
                })?)
                .ok_or_else(|| anyhow!("zkp-batch {zkp_index} end overflows usize"))?;
        let batch_values = values
            .get(start..end)
            .ok_or_else(|| anyhow!("queued nullifier slice {start}..{end} out of range"))?;
        let hash_chain = snapshot
            .hash_chains
            .get(
                usize::try_from(i)
                    .map_err(|_| anyhow!("ready zkp-batch index {i} exceeds usize"))?,
            )
            .copied()
            .ok_or_else(|| anyhow!("missing hash chain for ready zkp-batch {i}"))?;
        let old_root = reference.root();

        let (inputs, new_root) = build_inputs(
            &mut reference,
            batch_next_index,
            snapshot.height,
            hash_chain,
            old_root,
            batch_values,
        )?;

        let proof = prover
            .prove_batch_address_append(&inputs)
            .map_err(|err| anyhow!("prove zkp-batch {zkp_index}: {err}"))?;
        let compressed = ProofCompressed::try_from(proof)
            .map_err(|err| anyhow!("compress proof for zkp-batch {zkp_index}: {err:?}"))?;

        let signature = batch_update_nullifier_tree_once(ForestParams {
            rpc_url,
            member,
            settings,
            account_index,
            pool_tree: tree,
            batch_update: BatchUpdateNullifierTreeData {
                new_root,
                old_root,
                // `zkp_index` is bounded by the batch's `num_zkp_batches`
                // (= batch_size / zkp_batch_size), well within `u16`, so the
                // cast cannot truncate.
                zkp_batch_index: zkp_index as u16,
                compressed_proof: CompressedProof {
                    a: compressed.a,
                    b: compressed.b,
                    c: compressed.c,
                },
            },
        })
        .map_err(|err| anyhow!("submit zkp-batch {zkp_index}: {err}"))?;

        tracing::info!(%signature, zkp_index, new_root = %hex::encode(new_root), "submitted nullifier batch update");
        submitted += 1;
    }

    Ok(DrainOutcome::Drained(submitted))
}

/// Preflight: validate the tree-read / photon / reconstruct / root-match path
/// and report, without proving or submitting. Works even with no ready
/// zkp-batches, so it is a cheap way to check the integration end to end.
fn check_once(rpc_url: &str, photon: &BlockingZolanaApi, tree: Pubkey) -> Result<()> {
    let snapshot = read_snapshot(rpc_url, tree)?;
    let applied = applied_count(&snapshot)?;
    // Fetch the applied prefix plus the pending batch's queued values so the
    // report reflects the full known queue depth.
    let fetch_total = applied + snapshot.pending_queued;
    let (reference, values) = reconstruct_and_verify(photon, tree, &snapshot, fetch_total)?;

    println!("forester dry-run for tree {tree}");
    println!(
        "  on-chain nullifier root:  {}",
        hex::encode(snapshot.on_chain_root)
    );
    println!(
        "  reconstructed root:       {} (matches on-chain)",
        hex::encode(reference.root())
    );
    println!(
        "  height={}  zkp_batch_size={}",
        snapshot.height, snapshot.zkp_batch_size
    );
    println!("  appended (applied):            {applied}");
    println!("  photon queued values returned: {}", values.len());
    println!(
        "  pending batch queued:          {}",
        snapshot.pending_queued
    );
    println!("  ready zkp-batches:             {}", snapshot.ready);
    if snapshot.ready == 0 {
        let remaining = snapshot
            .zkp_batch_size
            .saturating_sub(snapshot.pending_queued);
        println!(
            "  => nothing ready to forest yet (~{remaining} more nullifiers to fill a zkp-batch)"
        );
    } else {
        println!("  => would prove & submit {} zkp-batch(es)", snapshot.ready);
    }
    Ok(())
}

/// Build the batch address-append witness for one zkp-batch, appending its
/// values into `reference`. Ported from `nullifier_tree.rs::build_inputs`.
fn build_inputs(
    reference: &mut ReferenceNullifierTree,
    next_index: u64,
    height: u32,
    leaves_hash_chain: [u8; 32],
    old_root: [u8; 32],
    batch_values: &[[u8; 32]],
) -> Result<(BatchAddressAppendInputs, [u8; 32])> {
    let mut low_element_values = Vec::with_capacity(batch_values.len());
    let mut low_element_indices = Vec::with_capacity(batch_values.len());
    let mut low_element_next_values = Vec::with_capacity(batch_values.len());
    let mut new_element_values = Vec::with_capacity(batch_values.len());
    let mut low_element_proofs = Vec::with_capacity(batch_values.len());
    let mut new_element_proofs = Vec::with_capacity(batch_values.len());

    for (offset, value_bytes) in batch_values.iter().enumerate() {
        let value = BigUint::from_bytes_be(value_bytes);
        let non_inclusion = reference
            .get_non_inclusion_proof(&value)
            .map_err(|err| anyhow!("non-inclusion proof: {err:?}"))?;
        low_element_values.push(BigUint::from_bytes_be(
            &non_inclusion.leaf_lower_range_value,
        ));
        low_element_indices.push(BigUint::from(non_inclusion.leaf_index as u64));
        low_element_next_values.push(BigUint::from_bytes_be(
            &non_inclusion.leaf_higher_range_value,
        ));
        low_element_proofs.push(path_to_biguint(non_inclusion.merkle_proof));
        new_element_values.push(value.clone());

        reference
            .append(&value)
            .map_err(|err| anyhow!("append nullifier: {err:?}"))?;
        let new_index = next_index as usize + offset;
        let new_proof = reference
            .get_proof_of_leaf(new_index, true)
            .map_err(|err| anyhow!("proof of leaf {new_index}: {err:?}"))?;
        new_element_proofs.push(path_to_biguint(new_proof));
    }

    let new_root = reference.root();
    let mut start_index_bytes = [0u8; 32];
    start_index_bytes[24..].copy_from_slice(&next_index.to_be_bytes());
    let public_input_hash =
        create_hash_chain_from_array([old_root, new_root, leaves_hash_chain, start_index_bytes])
            .map_err(|err| anyhow!("public input hash chain: {err:?}"))?;

    Ok((
        BatchAddressAppendInputs {
            public_input_hash: BigUint::from_bytes_be(&public_input_hash),
            old_root: BigUint::from_bytes_be(&old_root),
            new_root: BigUint::from_bytes_be(&new_root),
            hashchain_hash: BigUint::from_bytes_be(&leaves_hash_chain),
            start_index: next_index,
            low_element_values,
            low_element_indices,
            low_element_next_values,
            new_element_values,
            low_element_proofs,
            new_element_proofs,
            tree_height: height,
            batch_size: batch_values.len() as u32,
        },
        new_root,
    ))
}

fn reference_nullifier_tree(height: u32) -> Result<ReferenceNullifierTree> {
    let init_next_value = BigUint::from_str_radix(NULLIFIER_INIT_NEXT_VALUE_DEC, 10)
        .expect("nullifier init next value is a valid decimal constant");
    IndexedMerkleTree::<Poseidon, usize>::new_with_next_value(height as usize, 0, init_next_value)
        .map_err(|err| anyhow!("init reference nullifier tree: {err:?}"))
}

fn path_to_biguint(path: Vec<[u8; 32]>) -> Vec<BigUint> {
    path.into_iter()
        .map(|node| BigUint::from_bytes_be(&node))
        .collect()
}

/// Resolve the forester signing keypair from `PAYER` (a JSON byte array, as in
/// `info`). Required for `run`: the update must be signed by the tree's
/// configured forester authority.
fn forester_keypair() -> Result<Keypair> {
    let payer = env::var("PAYER").context("PAYER is not set (forester signing keypair)")?;
    crate::parse_payer_keypair(&payer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_batched_merkle_tree::constants::NULLIFIER_TREE_INIT_ROOT_40;

    fn nullifier(byte: u8) -> [u8; 32] {
        let mut value = [0u8; 32];
        value[31] = byte;
        value
    }

    #[test]
    fn reference_tree_matches_on_chain_init() {
        // Pins NULLIFIER_INIT_NEXT_VALUE_DEC: the reconstructed empty tree must
        // reproduce the on-chain initial root, or every run would (safely) bail.
        let reference = reference_nullifier_tree(40).unwrap();
        assert_eq!(reference.root(), NULLIFIER_TREE_INIT_ROOT_40);
    }

    #[test]
    fn indexed_value_shortage_is_typed_not_ready() {
        let Some(not_ready) = indexed_value_shortage(1, 2, "ready zkp-batch") else {
            panic!("short queue must be classified as not ready");
        };

        assert_eq!(not_ready, PhotonIndexNotReady::new(1, 2, "ready zkp-batch"));
        assert!(indexed_value_shortage(2, 2, "ready zkp-batch").is_none());
    }

    #[test]
    fn build_inputs_chains_roots_across_zkp_batches() {
        let mut reference = reference_nullifier_tree(40).unwrap();
        let values: Vec<[u8; 32]> = (1..=4u8).map(nullifier).collect();

        // Two zkp-batches of two, starting at leaf index 1 (init at 0).
        let old0 = reference.root();
        let first_batch = values.get(0..2).unwrap();
        let (inputs0, new0) =
            build_inputs(&mut reference, 1, 40, [0u8; 32], old0, first_batch).unwrap();
        assert_eq!(inputs0.batch_size, 2);
        assert_eq!(inputs0.start_index, 1);

        // The next batch's old_root must chain from the previous new_root.
        let old1 = reference.root();
        assert_eq!(old1, new0);
        let second_batch = values.get(2..4).unwrap();
        let (inputs1, new1) =
            build_inputs(&mut reference, 3, 40, [0u8; 32], old1, second_batch).unwrap();
        assert_eq!(inputs1.start_index, 3);

        // Appending all four to a fresh tree yields the same final root.
        let mut full = reference_nullifier_tree(40).unwrap();
        for value in &values {
            full.append(&BigUint::from_bytes_be(value)).unwrap();
        }
        assert_eq!(new1, full.root());
    }
}
