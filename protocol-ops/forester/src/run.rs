//! `forester run`: prove and submit ready nullifier-tree zkp-batches.
//!
//! The nullifier tree is a batched indexed Merkle tree: transfers queue
//! nullifiers, and the forester periodically appends a full zkp-batch of them
//! into the tree via `batch_update_nullifier_tree`, advancing the root. Proving
//! an append needs low-/new-element non-membership proofs against the tree
//! state *before* that batch, which the on-chain account does not retain.
//!
//! We rebuild that state the same way
//! `program-libs/tree/tests/nullifier_tree/prover_e2e.rs` does: replay the
//! ordered queued nullifier values (served by photon) into an in-memory
//! reference `IndexedMerkleTree`, verify the reconstructed root matches the
//! on-chain root, then build each ready zkp-batch's witness, prove it on the
//! forester prover, and submit the updates in root order.
//!
//! Only one of the three stages is ordered. Witness construction is sequential,
//! because a batch's `old_root` is the previous batch's `new_root`. Proving
//! depends on nothing but its own witness. Submission is unordered: the program
//! caches a verified update at its `zkp_batch_index` and applies whatever has
//! become contiguous, so a later batch may land first and wait, and a gap left
//! by a failed proof heals on the next pass.
//!
//! So `drain_once` serialises witness construction alone and runs
//! `proof_concurrency` prove-and-submit workers alongside it.

use spr_forester_prover::indexed::{
    BatchAnchor, IndexedBatchRequest, ProofDataSource, ProvenIndexedBatch,
};

use std::{
    collections::VecDeque,
    fmt,
    sync::atomic::{AtomicU64, Ordering},
    thread::{self, ScopedJoinHandle},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use num_bigint::BigUint;
use solana_commitment_config::CommitmentConfig;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signer::Signer;
use spr_forester_prover::{BatchAddressAppendInputs, Error as ProverError, ProverClient};
use spr_interface::instruction::BatchUpdateNullifierTreeData;
use spr_tree::{TreeAccount, TreeFeeSchedule};

use spr_forester_prover::{build_inputs, reference_nullifier_tree, ReferenceNullifierTree};

use crate::photon::{PhotonClient, PAGE_LIMIT};
use crate::{
    config::ForesterConfig,
    forest::{batch_update_nullifier_tree_once, ForestError, ForestParams},
};

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
    /// Zkp-batch proofs to run at once.
    ///
    /// This is the protocol's throughput knob. One proof clears
    /// `zkp_batch_size` nullifiers and takes about a minute, so proving them
    /// one at a time caps the whole pool at `zkp_batch_size / 60` spends per
    /// second — 4.2/s on devnet, against a client comfortably sustaining 24.
    /// Above that the queue only fills, and once full the program rejects
    /// spends outright with `NullifierTreeUpdateFailed`.
    ///
    /// The ceiling on this is the prover fleet's memory, not the forester: a
    /// batch address-append proof needs on the order of 15GB, so raising it
    /// past what the fleet can hold just moves the queueing into the prover.
    pub proof_concurrency: usize,
    pub client_proof_data: bool,
}

/// Zkp-batch proofs in flight at once when unset.
///
/// Deliberately above 1 and well below the prover fleet's limit. One is the
/// behaviour this replaced; a large default would silently depend on a fleet
/// size that varies per environment.
pub const DEFAULT_PROOF_CONCURRENCY: usize = 4;

/// Read-once view of the nullifier tree's batch state.
struct TreeSnapshot {
    next_index: u64,
    height: u32,
    zkp_batch_size: u64,
    /// Elements one full batch holds: the denominator for queue fill.
    batch_capacity: u64,
    already_applied: u64,
    ready: u64,
    pending_queued: u64,
    on_chain_root: [u8; 32],
    /// Leaves hash chain per ready zkp-batch, in order.
    hash_chains: Vec<[u8; 32]>,
    fees: TreeFeeSchedule,
    fee_balance: u64,
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

/// Drain ready nullifier zkp-batches for `opts.tree`. Endpoints and credentials
/// come from `config`, resolved at the process boundary. HTTP and local gnark
/// proving block, so this runs on ordinary worker threads.
pub fn run(config: &ForesterConfig, opts: RunOptions) -> Result<()> {
    let rpc_url = config.rpc_url.clone();
    let photon = PhotonClient::new(config.photon_url.clone())?;

    if opts.dry_run {
        return check_once(&rpc_url, &photon, opts.tree);
    }

    let settings = opts
        .settings
        .ok_or_else(|| anyhow!("--settings (forester smart-account) is required to submit"))?;
    let member = config.signer()?;
    let tree_label = opts.tree.to_string();
    // Batch proofs carry only public tree data, so the forester's prover runs
    // outside an enclave.
    let prover = config
        .prover()?
        .with_proof_data_source(if opts.client_proof_data {
            ProofDataSource::Client
        } else {
            ProofDataSource::Prover
        });

    tracing::info!(tree = %opts.tree, "forester run: draining nullifier queue");

    let submitted_total = AtomicU64::new(0);
    let mut keys_checked = false;
    let mut indexed_checked = prover.proof_data_source() == ProofDataSource::Client;
    // Carried across passes: see ReferenceCache.
    let mut cache = ReferenceCache::default();
    loop {
        // Liveness. Without this, "is the forester running?" is only answerable
        // by reading logs.
        crate::metrics::mark_run();
        report_queue_and_balance(&rpc_url, &member, opts.tree);

        // A prover on another proving-key set would burn a batch proof that the
        // program's verifying key then rejects; refuse it before draining. The
        // check runs inside the loop, after the queue is reported, because the
        // batch prover scales to zero on that report: exiting here, as it used
        // to, kept the report from ever being scraped and the prover down.
        if !keys_checked {
            match prover.check_proving_keys() {
                Ok(keys) => {
                    tracing::info!(prefix = %keys.prefix, "prover key configuration checked");
                    keys_checked = true;
                }
                Err(err) => {
                    let err = anyhow::Error::new(err).context("prover proving-key check failed");
                    wait_or_fail(&opts, err)?;
                    continue;
                }
            }
        }
        if !indexed_checked {
            match prover.check_indexed() {
                Ok(()) => indexed_checked = true,
                Err(ProverError::ProverIndexerUnconfigured) => bail!(
                    "prover serves no indexed proofs, restart it with an indexer or pass --client-proof-data"
                ),
                Err(err) => {
                    let err = anyhow::Error::new(err).context("prover indexed check failed");
                    wait_or_fail(&opts, err)?;
                    continue;
                }
            }
        }

        let before = submitted_total.load(Ordering::Relaxed);
        let remaining = opts.max_batches.map(|max| max.saturating_sub(before));
        if matches!(remaining, Some(0)) {
            tracing::info!(submitted_total = before, "reached --max-batches cap");
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
            opts.proof_concurrency,
            &mut cache,
            &submitted_total,
        );
        let landed = submitted_total.load(Ordering::Relaxed) - before;
        crate::metrics::count_batches_submitted(&tree_label, landed);
        if let Err(err) = outcome {
            wait_or_fail(&opts, err)?;
            continue;
        }

        if !opts.watch {
            break;
        }
        if landed == 0 {
            thread::sleep(Duration::from_secs(opts.poll_secs));
        }
    }

    tracing::info!(
        submitted_total = submitted_total.into_inner(),
        "forester run complete"
    );
    Ok(())
}

/// A Solana RPC read failed: the node was unreachable or answered with an
/// error.
#[derive(Debug, thiserror::Error)]
#[error("solana rpc unavailable: {0}")]
struct RpcUnavailable(String);

/// What a watching forester waits out, as the failure metric's `reason`: the
/// prover, its indexer, photon or the Solana RPC not being ready. The batch
/// prover scales to zero, and waiting on it is what keeps the forester
/// reporting the ready queue that scales it back up. A proving-key mismatch,
/// a bad witness or a rejected transaction stops the run.
fn retry_reason(err: &anyhow::Error) -> Option<&'static str> {
    err.chain().find_map(|cause| {
        if cause.is::<PhotonIndexNotReady>() {
            return Some("photon_index_not_ready");
        }
        if cause.is::<RpcUnavailable>()
            || matches!(
                cause.downcast_ref::<ForestError>(),
                Some(ForestError::Rpc(_))
            )
        {
            return Some("rpc_unavailable");
        }
        match cause.downcast_ref::<ProverError>()? {
            ProverError::IndexerProofDataNotReady => Some("prover_indexer_not_ready"),
            ProverError::ProverServer(_) => Some("prover_unavailable"),
            _ => None,
        }
    })
}

/// Waits out a failure a watching forester retries. Any other failure, and
/// every failure outside `--watch`, comes back.
fn wait_or_fail(opts: &RunOptions, err: anyhow::Error) -> Result<()> {
    let Some(reason) = retry_reason(&err).filter(|_| opts.watch) else {
        return Err(err);
    };
    crate::metrics::count_failure(reason);
    tracing::warn!(
        reason,
        err = %format_args!("{err:#}"),
        poll_secs = opts.poll_secs,
        "retrying"
    );
    thread::sleep(Duration::from_secs(opts.poll_secs));
    Ok(())
}

/// Publish queue depth, queue capacity, and payer balance for this iteration.
///
/// Metrics are observability: a failure here is logged and skipped rather than
/// propagated, so a metrics problem can never stop the queue draining.
///
/// This re-reads the tree account that `drain_once` will read again, costing one
/// extra `getAccountInfo` per poll interval. That is deliberate: reporting from
/// inside the drain path would skip publication on exactly the iterations that
/// fail, which are the ones worth observing. At a seconds-scale poll interval the
/// duplicate read is negligible next to proving.
fn report_queue_and_balance(rpc_url: &str, member: &Keypair, tree: Pubkey) {
    let tree_label = tree.to_string();
    match read_snapshot(rpc_url, tree) {
        Ok(snapshot) => {
            // `pending_queued` counts elements inserted into the pending batch, so
            // the denominator is that batch's element capacity. Both come from the
            // same batch, which makes length/capacity a fill ratio in [0, 1].
            crate::metrics::set_queue(
                &tree_label,
                snapshot.pending_queued,
                snapshot.batch_capacity,
            );
            // Was published as forester_indexer_proof_count{metric="ready_zkp_batches"}:
            // a queue statistic riding on an indexer metric, and the `metric`
            // label is not one of the forester's CloudWatch dimensions, so it
            // was dropped at the edge. These have their own names now, and the
            // existing `^queue_.*$` selector picks them up unchanged.
            crate::metrics::set_zkp_batches(
                &tree_label,
                snapshot.zkp_batch_size,
                snapshot.ready,
                snapshot.already_applied,
            );
        }
        Err(err) => tracing::debug!(%err, "metrics: tree snapshot unavailable"),
    }

    let rpc = RpcClient::new(rpc_url.to_string());
    match rpc.get_balance(&member.pubkey()) {
        Ok(lamports) => {
            crate::metrics::set_sol_balance(&member.pubkey().to_string(), lamports);
        }
        Err(err) => tracing::debug!(%err, "metrics: payer balance unavailable"),
    }
}

/// Read the nullifier tree's batch state and the ready zkp-batches' hash chains.
fn read_snapshot(rpc_url: &str, tree: Pubkey) -> Result<TreeSnapshot> {
    let rpc = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
    let mut data = rpc
        .get_account_with_commitment(&tree, CommitmentConfig::confirmed())
        .map_err(|err| RpcUnavailable(format!("fetch tree account {tree}: {err}")))?
        .value
        .ok_or_else(|| anyhow!("tree account not found: {tree}"))?
        .data;

    let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes())
        .map_err(|err| anyhow!("parse tree account {tree}: {err:?}"))?;
    let fees = account.fees();
    let fee_balance = account.fee_balance();
    let nullifier = account.nullifier_tree();
    let on_chain_root = nullifier
        .get_root()
        .ok_or_else(|| anyhow!("nullifier tree has no root"))?;

    let pending = nullifier.pending_batch_index as usize;
    let zkp_batch_size = nullifier.zkp_batch_size;
    let batch_capacity = nullifier.batch_size;
    let batch = *nullifier
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
        next_index: nullifier.next_index,
        height: nullifier.height,
        zkp_batch_size,
        batch_capacity,
        already_applied,
        ready,
        pending_queued,
        on_chain_root,
        hash_chains,
        fees,
        fee_balance,
    })
}

pub const LAMPORTS_PER_SIGNATURE: u64 = 5_000;

pub fn reimbursement_shortfall(append_reimbursement: u64, fee_balance: u64, batches: u64) -> u64 {
    append_reimbursement
        .saturating_mul(batches)
        .saturating_sub(fee_balance)
}

pub fn append_reimbursement_below_base_cost(append_reimbursement: u64) -> bool {
    append_reimbursement < LAMPORTS_PER_SIGNATURE
}

/// Nullifiers already appended into the tree; the init element occupies leaf 0.
fn applied_count(snapshot: &TreeSnapshot) -> Result<u64> {
    snapshot
        .next_index
        .checked_sub(1)
        .ok_or_else(|| anyhow!("nullifier tree next_index is 0 (uninitialized)"))
}

/// Fetch the requested queue prefix in API-sized pages. A short page returns
/// the currently indexed prefix so callers can classify indexer lag.
fn fetch_nullifier_values(
    photon: &PhotonClient,
    tree: Pubkey,
    fetch_total: u64,
) -> Result<Vec<[u8; 32]>> {
    let tree_account = tree;
    collect_nullifier_pages(fetch_total, |start_seq, limit| {
        let response = photon
            .get_nullifier_queue_elements(tree_account, Some(start_seq), limit)
            .map_err(|err| {
                anyhow!("fetch queued nullifiers from photon at sequence {start_seq}: {err}")
            })?;
        Ok(response
            .elements
            .into_iter()
            .map(|element| (element.seq, element.value.0))
            .collect())
    })
}

fn collect_nullifier_pages(
    fetch_total: u64,
    mut fetch_page: impl FnMut(u64, u64) -> Result<Vec<(u64, [u8; 32])>>,
) -> Result<Vec<[u8; 32]>> {
    let mut values = Vec::new();
    // Queue sequences equal leaf indices and start at 1, so the first
    // `fetch_total` values occupy sequences `1..=fetch_total`.
    let mut next_seq = 1u64;
    let end_seq = fetch_total
        .checked_add(1)
        .ok_or_else(|| anyhow!("queued nullifier sequence overflow"))?;

    while next_seq < end_seq {
        let page_limit = (end_seq - next_seq).min(PAGE_LIMIT);
        let page = fetch_page(next_seq, page_limit)?;
        let returned =
            u64::try_from(page.len()).map_err(|_| anyhow!("photon page length exceeds u64"))?;
        if returned > page_limit {
            bail!("photon returned {returned} nullifiers after sequence {next_seq}, requested at most {page_limit}");
        }

        for (seq, value) in page {
            if seq != next_seq {
                bail!("queued nullifier sequence gap: expected {next_seq}, photon returned {seq}");
            }
            values.push(value);
            next_seq = next_seq
                .checked_add(1)
                .ok_or_else(|| anyhow!("queued nullifier sequence overflow"))?;
        }

        if returned < page_limit {
            break;
        }
    }

    Ok(values)
}

/// Fetch queued values from photon, replay the already-appended prefix into a
/// fresh reference tree, and verify the reconstructed root matches on-chain.
/// Returns the reference tree (at the on-chain state) and the fetched values.
/// The replayed nullifier tree, kept between drain passes.
///
/// Rebuilding it means appending every already-applied nullifier again --
/// sequential, Poseidon-heavy, and single-threaded. At ~30k applied values it
/// pegged the forester's core for over ten minutes per pass while the prover
/// sat at 0.002%, and the cost grows with every batch ever forested. Carrying
/// the tree forward makes the usual pass append nothing.
#[derive(Default)]
struct ReferenceCache {
    /// `None` until the first successful reconstruction.
    tree: Option<ReferenceNullifierTree>,
    /// How many queued values `tree` holds. Not the applied count: a drain pass
    /// advances the tree through every witness it builds, including batches
    /// whose submission then failed.
    appended: u64,
}

impl ReferenceCache {
    /// Extend the tree to hold exactly `applied` values, rebuilding it only
    /// when it cannot be extended.
    ///
    /// An `IndexedMerkleTree` only appends, so a tree that has run ahead of the
    /// chain -- a witness was built for a batch that never landed -- cannot be
    /// rewound and is rebuilt. That is the self-healing path, not the common
    /// one: when every batch lands, `appended` and `applied` meet exactly.
    fn advance_to(&mut self, applied: u64, values: &[[u8; 32]], height: u32) -> Result<()> {
        if self.appended > applied {
            tracing::info!(
                appended = self.appended,
                applied,
                "reference tree is ahead of chain; rebuilding"
            );
            self.invalidate();
        }

        let mut tree = match self.tree.take() {
            Some(tree) => tree,
            None => reference_nullifier_tree(height)?,
        };
        let from = usize::try_from(self.appended)
            .map_err(|_| anyhow!("appended nullifier count {} exceeds usize", self.appended))?;
        let pending = values
            .get(from..)
            .ok_or_else(|| anyhow!("queued nullifier prefix is shorter than {from}"))?;
        for value in pending {
            tree.append(&BigUint::from_bytes_be(value))
                .map_err(|err| anyhow!("replay appended nullifier: {err:?}"))?;
        }

        self.appended = applied;
        self.tree = Some(tree);
        Ok(())
    }

    fn tree_mut(&mut self) -> Result<&mut ReferenceNullifierTree> {
        self.tree
            .as_mut()
            .ok_or_else(|| anyhow!("reference tree is not reconstructed"))
    }

    fn root(&self) -> Result<[u8; 32]> {
        self.tree
            .as_ref()
            .map(|tree| tree.root())
            .ok_or_else(|| anyhow!("reference tree is not reconstructed"))
    }

    /// Record how far a drain pass advanced the tree past the applied count.
    fn advanced_by(&mut self, values: u64) {
        self.appended = self.appended.saturating_add(values);
    }

    /// Drop the tree so the next pass rebuilds it.
    fn invalidate(&mut self) {
        self.tree = None;
        self.appended = 0;
    }
}

/// Fetch the queued nullifiers and bring `cache` up to the chain's applied
/// count, verifying that the replay reproduces the on-chain root.
fn reconstruct_and_verify(
    photon: &PhotonClient,
    tree: Pubkey,
    snapshot: &TreeSnapshot,
    fetch_total: u64,
    cache: &mut ReferenceCache,
) -> Result<Vec<[u8; 32]>> {
    let applied = applied_count(snapshot)?;
    let values = fetch_nullifier_values(photon, tree, fetch_total)?;
    if let Some(not_ready) = indexed_value_shortage(
        values.len(),
        applied,
        format!("the {applied} already-applied nullifiers required to reconstruct"),
    ) {
        return Err(not_ready.into());
    }

    let applied_len = usize::try_from(applied)
        .map_err(|_| anyhow!("applied nullifier count {applied} exceeds usize"))?;
    let applied_values = values
        .get(..applied_len)
        .ok_or_else(|| anyhow!("queued nullifier prefix length {applied_len} out of range"))?;

    cache.advance_to(applied, applied_values, snapshot.height)?;
    let reconstructed = cache.root()?;
    if reconstructed != snapshot.on_chain_root {
        // A carried-forward tree that disagrees must not poison the next pass.
        cache.invalidate();
        bail!(
            "reconstructed nullifier root {} does not match on-chain root {}; refusing to proceed",
            hex::encode(reconstructed),
            hex::encode(snapshot.on_chain_root)
        );
    }
    Ok(values)
}

/// Wait for one in-flight proof, turning a panicked worker into an error.
fn join_proof(handle: ScopedJoinHandle<'_, Result<()>>) -> Result<()> {
    handle
        .join()
        .unwrap_or_else(|_| bail!("proving thread panicked"))
}

enum PendingBatch {
    Client {
        inputs: Box<BatchAddressAppendInputs>,
        old_root: [u8; 32],
        new_root: [u8; 32],
    },
    Prover(IndexedBatchRequest),
}

impl PendingBatch {
    fn prove(self, prover: &ProverClient) -> Result<ProvenIndexedBatch> {
        match self {
            Self::Prover(request) => Ok(prover.prove_indexed(&request)?),
            Self::Client {
                inputs,
                old_root,
                new_root,
            } => {
                let proof = prover.prove_batch_address_append(&inputs)?;
                Ok(ProvenIndexedBatch {
                    old_root,
                    new_root,
                    proof,
                })
            }
        }
    }
}

/// One drain pass: prove+submit the pending batch's ready zkp-batches (capped by
/// `limit`), counting each that lands in `submitted`.
#[allow(clippy::too_many_arguments)]
fn drain_once(
    rpc_url: &str,
    prover: &ProverClient,
    photon: &PhotonClient,
    member: &Keypair,
    settings: Pubkey,
    account_index: u8,
    tree: Pubkey,
    limit: Option<u64>,
    proof_concurrency: usize,
    cache: &mut ReferenceCache,
    submitted: &AtomicU64,
) -> Result<()> {
    let snapshot = read_snapshot(rpc_url, tree)?;
    if snapshot.ready == 0 {
        tracing::info!("no ready zkp-batches to forest");
        return Ok(());
    }
    tracing::info!(
        ready = snapshot.ready,
        zkp_batch_size = snapshot.zkp_batch_size,
        "ready zkp-batches"
    );

    let applied = applied_count(&snapshot)?;
    let needed = applied + snapshot.ready * snapshot.zkp_batch_size;
    let values = if prover.proof_data_source() == ProofDataSource::Client {
        let values = reconstruct_and_verify(photon, tree, &snapshot, needed, cache)?;
        if let Some(not_ready) =
            indexed_value_shortage(values.len(), needed, format!("applied {applied}"))
        {
            return Err(not_ready.into());
        }
        Some(values)
    } else {
        None
    };

    let cap = limit
        .map(|limit| limit.min(snapshot.ready))
        .unwrap_or(snapshot.ready);
    let concurrency = proof_concurrency.max(1);

    let tree_label = tree.to_string();
    crate::metrics::set_fee_schedule(
        &tree_label,
        snapshot.fees.append_reimbursement,
        snapshot.fee_balance,
    );
    if append_reimbursement_below_base_cost(snapshot.fees.append_reimbursement) {
        tracing::warn!(
            append_reimbursement = snapshot.fees.append_reimbursement,
            base_fee = LAMPORTS_PER_SIGNATURE,
            "append reimbursement is below the base transaction fee; forester runs below cost"
        );
    }
    let shortfall = reimbursement_shortfall(
        snapshot.fees.append_reimbursement,
        snapshot.fee_balance,
        cap,
    );
    if shortfall > 0 {
        crate::metrics::add_reimbursement_shortfall(&tree_label, shortfall);
        tracing::warn!(
            shortfall,
            fee_balance = snapshot.fee_balance,
            append_reimbursement = snapshot.fees.append_reimbursement,
            batches = cap,
            "tree fee balance does not cover the append reimbursement for this pass"
        );
    }

    // Build the next witness while the previous proofs are still running.
    //
    // Each stage has a different constraint, and only one of them is ordering:
    //
    //   witness  sequential -- a batch's `old_root` is the previous batch's
    //            `new_root`, so the reference tree must be walked in order.
    //   prove    independent -- a proof reads only its own witness.
    //   submit   unordered -- the program caches a verified update at its
    //            `zkp_batch_index` and applies whatever has become contiguous,
    //            so a later batch may land first and simply wait. A mismatched
    //            `old_root` is evicted rather than rejected, so a gap left by a
    //            failed proof heals on the next pass.
    //
    // So proving and submitting both belong to the worker, and the only thing
    // this loop serialises is witness construction. An earlier version proved in
    // fixed groups and submitted in order, which measured no faster than proving
    // one at a time: building a group's witnesses pegged the forester's single
    // core while the prover idled, then the prover ran while the forester idled.
    // Overlapping them is the entire point.
    let result = thread::scope(|scope| -> Result<()> {
        let mut in_flight = VecDeque::with_capacity(concurrency);
        for i in 0..cap {
            // Bound the window by retiring the oldest proof before starting
            // another. Proof durations are near-identical, so taking them in
            // order costs nothing a completion queue would save.
            if in_flight.len() == concurrency {
                if let Some(oldest) = in_flight.pop_front() {
                    join_proof(oldest)?;
                }
            }

            let zkp_index = snapshot.already_applied + i;
            let batch_next_index = snapshot.next_index + i * snapshot.zkp_batch_size;
            let hash_chain = snapshot
                .hash_chains
                .get(
                    usize::try_from(i)
                        .map_err(|_| anyhow!("ready zkp-batch index {i} exceeds usize"))?,
                )
                .copied()
                .ok_or_else(|| anyhow!("missing hash chain for ready zkp-batch {i}"))?;
            let batch = if let Some(values) = &values {
                let start = usize::try_from(applied + i * snapshot.zkp_batch_size)
                    .map_err(|_| anyhow!("zkp-batch {zkp_index} start exceeds usize"))?;
                let end = start
                    .checked_add(usize::try_from(snapshot.zkp_batch_size).map_err(|_| {
                        anyhow!("zkp_batch_size {} exceeds usize", snapshot.zkp_batch_size)
                    })?)
                    .ok_or_else(|| anyhow!("zkp-batch {zkp_index} end overflows usize"))?;
                let batch_values = values
                    .get(start..end)
                    .ok_or_else(|| anyhow!("queued nullifier slice {start}..{end} out of range"))?;
                let reference = cache.tree_mut()?;
                let old_root = reference.root();
                let (inputs, new_root) = build_inputs(
                    reference,
                    batch_next_index,
                    snapshot.height,
                    hash_chain,
                    old_root,
                    batch_values,
                )?;
                PendingBatch::Client {
                    inputs: Box::new(inputs),
                    old_root,
                    new_root,
                }
            } else {
                PendingBatch::Prover(IndexedBatchRequest {
                    previous_batches: snapshot.hash_chains[..usize::try_from(i)?].to_vec(),
                    tree: tree.to_bytes().into(),
                    tree_height: snapshot.height,
                    batch_size: u32::try_from(snapshot.zkp_batch_size)?,
                    start_index: batch_next_index,
                    anchor: BatchAnchor {
                        next_index: snapshot.next_index,
                        root: snapshot.on_chain_root,
                    },
                    leaves_hash_chain: hash_chain,
                })
            };

            // Scoped threads rather than an async runtime: the prover client is
            // blocking, and `run` is documented to run on a plain thread.
            in_flight.push_back(scope.spawn(move || {
                // Kept typed, so the run loop can tell an unavailable prover apart.
                let ProvenIndexedBatch {
                    old_root,
                    new_root,
                    proof: batch_update_proof,
                } = batch
                    .prove(prover)
                    .with_context(|| format!("prove zkp-batch {zkp_index}"))?;

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
                        // (= batch_size / zkp_batch_size), well within `u16`, so
                        // the cast cannot truncate.
                        zkp_batch_index: zkp_index as u16,
                        proof: batch_update_proof,
                    },
                })
                .with_context(|| format!("submit zkp-batch {zkp_index}"))?;

                submitted.fetch_add(1, Ordering::Relaxed);
                tracing::info!(
                    %signature,
                    zkp_index,
                    new_root = %hex::encode(new_root),
                    "submitted nullifier batch update"
                );
                Ok(())
            }));
        }

        in_flight.into_iter().try_for_each(join_proof)
    });

    // Every witness built advanced the tree, whether or not its batch landed:
    // a full pass by `cap` batches, an interrupted one by an unknown number.
    if values.is_some() {
        match &result {
            Ok(()) => cache.advanced_by(cap * snapshot.zkp_batch_size),
            Err(_) => cache.invalidate(),
        }
    }
    result
}

/// Preflight: validate the tree-read / photon / reconstruct / root-match path
/// and report, without proving or submitting. Works even with no ready
/// zkp-batches, so it is a cheap way to check the integration end to end.
fn check_once(rpc_url: &str, photon: &PhotonClient, tree: Pubkey) -> Result<()> {
    let snapshot = read_snapshot(rpc_url, tree)?;
    let applied = applied_count(&snapshot)?;
    // Fetch the applied prefix plus the pending batch's queued values so the
    // report reflects the full known queue depth.
    let fetch_total = applied + snapshot.pending_queued;
    let mut cache = ReferenceCache::default();
    let values = reconstruct_and_verify(photon, tree, &snapshot, fetch_total, &mut cache)?;
    let reference = cache.tree_mut()?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use spr_tree::nullifier_tree::constants::NULLIFIER_TREE_INIT_ROOT_40;

    fn nullifier(byte: u8) -> [u8; 32] {
        let mut value = [0u8; 32];
        value[31] = byte;
        value
    }

    #[test]
    fn a_watching_forester_waits_out_only_what_can_come_back() {
        let retried = [
            (
                anyhow::Error::new(RpcUnavailable("fetch tree account x: 530".into())),
                "rpc_unavailable",
            ),
            (
                anyhow::Error::new(ForestError::Rpc("530".into())).context("submit zkp-batch 0"),
                "rpc_unavailable",
            ),
            (
                anyhow::Error::new(ProverError::ProverServer("request failed".into()))
                    .context("prove zkp-batch 3"),
                "prover_unavailable",
            ),
            (
                anyhow::Error::new(ProverError::IndexerProofDataNotReady)
                    .context("prove zkp-batch 3"),
                "prover_indexer_not_ready",
            ),
            (
                PhotonIndexNotReady::new(1, 2, "ready zkp-batch").into(),
                "photon_index_not_ready",
            ),
        ];
        for (err, reason) in retried {
            assert_eq!(retry_reason(&err), Some(reason), "{err:#}");
        }
        let fatal = [
            anyhow::Error::new(ForestError::TxFailed("custom program error".into()))
                .context("submit zkp-batch 0"),
            anyhow::Error::new(ProverError::ProverProvingKeysMismatch {
                mismatches: vec!["transfer_ring_2_2.key".into()],
            }),
            anyhow::Error::new(ProverError::ProvingKeyMismatch {
                key: "batch_address-append_40_4999.key".into(),
                expected: "aa".into(),
                reported: "bb".into(),
            }),
            anyhow::Error::new(ProverError::Prover("failed to start prover".into())),
            anyhow!("parse tree account x: InvalidAccountData"),
            anyhow!("tree account not found: x"),
            anyhow!("reconstructed nullifier root does not match on-chain root"),
        ];
        for err in fatal {
            assert_eq!(retry_reason(&err), None, "{err:#}");
        }
    }

    #[test]
    fn a_proof_error_prints_its_context_and_cause_on_one_line() {
        let err = anyhow::Error::new(ProverError::ProverServer("request failed".into()))
            .context("prove zkp-batch 3");
        // main prints `{err:#}`; the log line reads as it did before.
        assert_eq!(
            format!("{err:#}"),
            "prove zkp-batch 3: prover server error: request failed"
        );
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
    fn nullifier_fetch_pages_past_the_api_limit() {
        let total = PAGE_LIMIT * 2 + 7;
        let mut requests = Vec::new();
        let values = collect_nullifier_pages(total, |start_seq, limit| {
            requests.push((start_seq, limit));
            Ok((start_seq..start_seq + limit)
                .map(|seq| {
                    let mut value = [0u8; 32];
                    value[24..].copy_from_slice(&seq.to_be_bytes());
                    (seq, value)
                })
                .collect())
        })
        .unwrap();

        assert_eq!(
            requests,
            vec![
                (1, PAGE_LIMIT),
                (1 + PAGE_LIMIT, PAGE_LIMIT),
                (1 + PAGE_LIMIT * 2, 7)
            ]
        );
        assert_eq!(values.len(), usize::try_from(total).unwrap());
        assert_eq!(values.last().unwrap()[24..], total.to_be_bytes());
    }

    #[test]
    fn empty_nullifier_fetch_skips_photon() {
        let values = collect_nullifier_pages(0, |_, _| {
            panic!("an empty prefix must not issue a Photon request")
        })
        .unwrap();
        assert!(values.is_empty());
    }

    fn appended(values: &[[u8; 32]]) -> [u8; 32] {
        let mut tree = reference_nullifier_tree(40).unwrap();
        for value in values {
            tree.append(&BigUint::from_bytes_be(value)).unwrap();
        }
        tree.root()
    }

    /// The point of the cache: a later pass appends only what is new.
    ///
    /// Replaying from zero costs one Poseidon-heavy append per already-applied
    /// nullifier, single-threaded. At ~30k applied it held the forester's core
    /// for over ten minutes per pass while the prover sat idle.
    #[test]
    fn a_later_pass_extends_the_tree_rather_than_replaying_it() {
        let values: Vec<[u8; 32]> = (1..=4u8).map(nullifier).collect();
        let mut cache = ReferenceCache::default();

        cache.advance_to(2, values.get(..2).unwrap(), 40).unwrap();
        assert_eq!(cache.root().unwrap(), appended(values.get(..2).unwrap()));

        cache.advance_to(4, &values, 40).unwrap();
        assert_eq!(cache.root().unwrap(), appended(&values));
    }

    /// A tree left ahead of the chain -- a witness was built for a batch whose
    /// submission then failed -- cannot be rewound, so the next pass starts over
    /// rather than carrying a state the chain never reached.
    #[test]
    fn a_tree_ahead_of_the_chain_is_rebuilt() {
        let values: Vec<[u8; 32]> = (1..=4u8).map(nullifier).collect();
        let mut cache = ReferenceCache::default();

        cache.advance_to(4, &values, 40).unwrap();
        cache.advanced_by(500);

        cache.advance_to(2, values.get(..2).unwrap(), 40).unwrap();
        assert_eq!(cache.root().unwrap(), appended(values.get(..2).unwrap()));
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

    /// Witnesses must be built in order even though their proofs are not.
    ///
    /// This is the invariant `drain_once` relies on to fan proving out: it
    /// builds a group of witnesses sequentially, then proves them together.
    /// Building them out of order would produce roots that chain to a state the
    /// chain never reaches, and every proof in the group would be rejected -- so
    /// the property is worth holding directly rather than inferring it from the
    /// happy path.
    #[test]
    fn a_group_of_witnesses_chains_head_to_tail() {
        let mut reference = reference_nullifier_tree(40).unwrap();
        let values: Vec<[u8; 32]> = (1..=6u8).map(nullifier).collect();

        // Three zkp-batches of two, the shape one concurrent group takes.
        let mut built = Vec::new();
        for (batch, chunk) in values.chunks(2).enumerate() {
            let next_index = 1 + (batch as u64) * 2;
            let old_root = reference.root();
            let (_, new_root) =
                build_inputs(&mut reference, next_index, 40, [0u8; 32], old_root, chunk).unwrap();
            built.push((old_root, new_root));
        }

        // Each batch continues from the one before, in order.
        for pair in built.windows(2) {
            let [(_, earlier_new), (later_old, _)] = pair else {
                unreachable!("windows(2) yields pairs")
            };
            assert_eq!(
                earlier_new, later_old,
                "a batch's old_root must be its predecessor's new_root"
            );
        }

        // And the group as a whole lands where appending every value does.
        let mut full = reference_nullifier_tree(40).unwrap();
        for value in &values {
            full.append(&BigUint::from_bytes_be(value)).unwrap();
        }
        let (_, last_new) = built.last().unwrap();
        assert_eq!(*last_new, full.root());
    }
}
