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
//! forester prover, and submit it before the next one is proved. Each on-chain
//! update checks `old_root == current root`, so submission is strictly
//! sequential, and every update that lands stays durable when a later one
//! fails.

use std::{env, fmt, thread, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use num_bigint::BigUint;
use num_traits::Num;
use solana_commitment_config::CommitmentConfig;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use zolana_batched_merkle_tree::verify::is_supported_batch_address_fold;
use zolana_client::{
    BatchAddressAppendInputs, FoldAppend, NullifierFoldInputs, Proof, ProofCompressed, ProverClient,
};
use zolana_hasher::{hash_chain::create_hash_chain_from_array, Poseidon};
use zolana_interface::instruction::{BatchUpdateNullifierTreeData, CompressedProof};
use zolana_merkle_tree::indexed::IndexedMerkleTree;
use zolana_tree::TreeAccount;

type ReferenceNullifierTree = IndexedMerkleTree<Poseidon, usize>;

use crate::forest::{
    batch_update_nullifier_tree_folded_once, batch_update_nullifier_tree_once, FoldedRun,
    ForestParams,
};
use zolana_api::{BlockingZolanaApi, SerializablePubkey, PAGE_LIMIT};

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
    /// Fold this many consecutive zkp-batches into one transaction. `None`
    /// submits one at a time. A run only folds when a fold key covers its
    /// length, so an uncovered remainder still submits singly.
    pub fold_run: Option<u32>,
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
    Drained(PassProgress),
    NotReady(PhotonIndexNotReady),
}

/// What one pass achieved. `stalled` holds the failure that ended the pass
/// before its cap. Everything counted in `submitted` is already on chain, so
/// the next pass starts from a fresh snapshot and only redoes the rest.
struct PassProgress {
    submitted: u64,
    stalled: Option<anyhow::Error>,
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

    let submitted_total = WatchLoop {
        watch: opts.watch,
        poll_secs: opts.poll_secs,
        max_batches: opts.max_batches,
    }
    .drive(
        |limit| {
            DrainPass {
                rpc_url: &rpc_url,
                prover: &prover,
                photon: &photon,
                member: &member,
                settings,
                account_index: opts.account_index,
                tree: opts.tree,
                limit,
                fold_run: opts.fold_run,
            }
            .run()
        },
        thread::sleep,
    )?;

    tracing::info!(submitted_total, "forester run complete");
    Ok(())
}

/// Repeats drain passes until the cap or, in `--watch` mode, forever.
struct WatchLoop {
    watch: bool,
    poll_secs: u64,
    max_batches: Option<u64>,
}

impl WatchLoop {
    /// Drive passes and return how many zkp-batches landed. A pass that stalls
    /// partway keeps what it submitted, so in `--watch` mode a prover or RPC
    /// failure costs one poll interval instead of the loop. Without `--watch`
    /// the stall is the exit status, because nothing retries it.
    fn drive(
        &self,
        mut pass: impl FnMut(Option<u64>) -> Result<DrainOutcome>,
        mut wait: impl FnMut(Duration),
    ) -> Result<u64> {
        let mut submitted_total: u64 = 0;
        loop {
            let remaining = self
                .max_batches
                .map(|max| max.saturating_sub(submitted_total));
            if matches!(remaining, Some(0)) {
                tracing::info!(submitted_total, "reached --max-batches cap");
                return Ok(submitted_total);
            }

            let progress = match pass(remaining)? {
                DrainOutcome::Drained(progress) => progress,
                DrainOutcome::NotReady(not_ready) => {
                    if !self.watch {
                        bail!("{not_ready}");
                    }
                    tracing::warn!(
                        %not_ready,
                        poll_secs = self.poll_secs,
                        "photon has not indexed enough nullifier queue elements; retrying"
                    );
                    wait(Duration::from_secs(self.poll_secs));
                    continue;
                }
            };
            submitted_total += progress.submitted;

            match progress.stalled {
                Some(err) if !self.watch => return Err(err),
                Some(err) => tracing::warn!(
                    error = %err,
                    submitted = progress.submitted,
                    submitted_total,
                    "drain pass stopped early; retrying the rest next pass"
                ),
                None if !self.watch => return Ok(submitted_total),
                None => {}
            }

            if progress.submitted == 0 {
                wait(Duration::from_secs(self.poll_secs));
            }
        }
    }
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

/// `base + count * stride` over counters read from the tree account. A wrap
/// would point the pass at the wrong queue slice, so it is an error.
fn offset_at(base: u64, count: u64, stride: u64) -> Result<u64> {
    count
        .checked_mul(stride)
        .and_then(|scaled| base.checked_add(scaled))
        .ok_or_else(|| anyhow!("nullifier queue offset {base} + {count} * {stride} overflows"))
}

/// Fetch the requested queue prefix in API-sized pages. A short page returns
/// the currently indexed prefix so callers can classify indexer lag.
fn fetch_nullifier_values(
    photon: &BlockingZolanaApi,
    tree: Pubkey,
    fetch_total: u64,
) -> Result<Vec<[u8; 32]>> {
    let tree_account = SerializablePubkey(tree);
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
    let mut next_seq = 0u64;

    while next_seq < fetch_total {
        let page_limit = (fetch_total - next_seq).min(PAGE_LIMIT);
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
fn reconstruct_and_verify(
    photon: &BlockingZolanaApi,
    tree: Pubkey,
    snapshot: &TreeSnapshot,
    fetch_total: u64,
) -> Result<(ReferenceNullifierTree, Vec<[u8; 32]>)> {
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

/// One drain pass.
struct DrainPass<'a> {
    rpc_url: &'a str,
    prover: &'a ProverClient,
    photon: &'a BlockingZolanaApi,
    member: &'a Keypair,
    settings: Pubkey,
    account_index: u8,
    tree: Pubkey,
    limit: Option<u64>,
    fold_run: Option<u32>,
}

impl DrainPass<'_> {
    fn run(self) -> Result<DrainOutcome> {
        let Self {
            rpc_url,
            prover,
            photon,
            member,
            settings,
            account_index,
            tree,
            limit,
            fold_run,
        } = self;
        let snapshot = read_snapshot(rpc_url, tree)?;
        // Every queue offset below scales by this size. A zero would make the
        // whole pass address leaf 0 of the queue over and over.
        if snapshot.zkp_batch_size == 0 {
            bail!("nullifier tree {tree} reports a zkp_batch_size of 0");
        }
        if let Some(run) = fold_run {
            if !is_supported_batch_address_fold(snapshot.height, snapshot.zkp_batch_size, run) {
                bail!(
                "unsupported folded nullifier configuration: height={}, batch_size={}, run={run}",
                snapshot.height,
                snapshot.zkp_batch_size
            );
            }
        }
        if snapshot.ready == 0 {
            tracing::info!("no ready zkp-batches to forest");
            return Ok(DrainOutcome::Drained(PassProgress {
                submitted: 0,
                stalled: None,
            }));
        }
        tracing::info!(
            ready = snapshot.ready,
            zkp_batch_size = snapshot.zkp_batch_size,
            "ready zkp-batches"
        );

        let cap = limit
            .map(|limit| limit.min(snapshot.ready))
            .unwrap_or(snapshot.ready);
        let applied = applied_count(&snapshot)?;
        // Only the capped range is fetched and replayed, so `--max-batches`
        // also bounds how far photon must have indexed.
        let needed = offset_at(applied, cap, snapshot.zkp_batch_size)?;
        let (reference, values) = match reconstruct_and_verify(photon, tree, &snapshot, needed) {
            Ok(reconstructed) => reconstructed,
            Err(err) => {
                let not_ready = err.downcast::<PhotonIndexNotReady>()?;
                return Ok(DrainOutcome::NotReady(not_ready));
            }
        };
        if let Some(not_ready) = indexed_value_shortage(
            values.len(),
            needed,
            format!("applied {applied} + {cap} ready zkp-batch(es)"),
        ) {
            return Ok(DrainOutcome::NotReady(not_ready));
        }

        let mut steps = ChainSteps {
            rpc_url,
            prover,
            member,
            settings,
            account_index,
            tree,
            snapshot,
            applied,
            values,
            reference,
        };
        Ok(DrainOutcome::Drained(drive_pass(&mut steps, cap, fold_run)))
    }
}

/// The prove and submit half of a pass. The driver owns the ordering and the
/// failure policy, so both are exercised without a validator or a prover.
trait DrainSteps {
    type Append;

    /// Prove the append `offset` batches into this pass. Called in order,
    /// because each append chains from the root the previous one produced.
    fn prove(&mut self, offset: u64) -> Result<Self::Append>;

    /// Settle a whole span in one transaction.
    fn submit_fold(&mut self, span: &[Self::Append], run: u32) -> Result<(), FoldFailure>;

    fn submit_single(&mut self, append: &Self::Append) -> Result<()>;
}

/// Why a folded submission failed. The span's single appends are proved
/// already, so a proving failure still has a way forward. A failed transaction
/// does not, because it can still land after the client stops waiting, and a
/// second attempt at the same span would then race the tree.
#[derive(Debug, thiserror::Error)]
enum FoldFailure {
    #[error("{0}")]
    Prove(anyhow::Error),
    #[error("{0}")]
    Submit(anyhow::Error),
}

/// Prove and submit up to `cap` zkp-batches, one span at a time, so each update
/// is durable before the next is proved. A failure ends the pass and returns
/// what landed. Every iteration either lands at least one update or returns, so
/// the loop cannot spin.
fn drive_pass<S: DrainSteps>(steps: &mut S, cap: u64, fold_run: Option<u32>) -> PassProgress {
    let mut submitted = 0u64;
    while submitted < cap {
        let span_run = fold_span(cap - submitted, fold_run);
        let (span, prove_stall) = prove_span(steps, submitted, span_run.map_or(1, u64::from));
        let (landed, submit_stall) = match span_run {
            // A short span has no fold key, so it settles one at a time.
            Some(run) if prove_stall.is_none() => submit_folded(steps, &span, run),
            _ => submit_singly(steps, &span),
        };
        submitted += landed;

        if let Some(stalled) = submit_stall.or(prove_stall) {
            return PassProgress {
                submitted,
                stalled: Some(stalled),
            };
        }
    }

    PassProgress {
        submitted,
        stalled: None,
    }
}

/// Prove `want` appends from `first`. A failure returns the appends proved
/// before it, which are still valid and still worth submitting.
fn prove_span<S: DrainSteps>(
    steps: &mut S,
    first: u64,
    want: u64,
) -> (Vec<S::Append>, Option<anyhow::Error>) {
    let mut span = Vec::new();
    for offset in first..first.saturating_add(want) {
        match steps.prove(offset) {
            Ok(append) => span.push(append),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    offset,
                    proved = span.len(),
                    "proving stopped; submitting what is proved"
                );
                return (span, Some(err));
            }
        }
    }
    (span, None)
}

fn submit_folded<S: DrainSteps>(
    steps: &mut S,
    span: &[S::Append],
    run: u32,
) -> (u64, Option<anyhow::Error>) {
    match steps.submit_fold(span, run) {
        Ok(()) => (u64::from(run), None),
        Err(FoldFailure::Prove(err)) => {
            tracing::warn!(error = %err, run, "fold proof failed; submitting the span singly");
            submit_singly(steps, span)
        }
        Err(FoldFailure::Submit(err)) => (0, Some(err)),
    }
}

fn submit_singly<S: DrainSteps>(steps: &mut S, span: &[S::Append]) -> (u64, Option<anyhow::Error>) {
    let mut landed = 0u64;
    for append in span {
        if let Err(err) = steps.submit_single(append) {
            // The tree root did not move, so every later append chains from a
            // root that is no longer next. The rest waits for a fresh pass.
            return (landed, Some(err));
        }
        landed += 1;
    }
    (landed, None)
}

/// How many of the next `available` appends to fold, or `None` to submit one at
/// a time.
///
/// A run only folds at exactly the configured length, because that length picks
/// the fold verifying key. A shorter tail has no key, so it falls back to
/// single submission rather than folding at some other width.
fn fold_span(available: u64, fold_run: Option<u32>) -> Option<u32> {
    let run = fold_run?;
    if run < 2 || available < u64::from(run) {
        return None;
    }
    Some(run)
}

/// One proved append, held until its span is submitted.
struct ProvedAppend {
    zkp_index: u64,
    old_root: [u8; 32],
    new_root: [u8; 32],
    hash_chain: [u8; 32],
    start_index: u64,
    proof: Proof,
    compressed: ProofCompressed,
}

/// Proves against the reference tree replayed from the pass snapshot and
/// submits to the chain.
///
/// Every `old_root` chains from that one snapshot, so the pass assumes the tree
/// does not advance under it. When another forester lands an update first, the
/// on-chain `old_root == current root` check rejects the submission, the pass
/// stops with what it landed, and the next pass reads the tree again. Proving
/// one span at a time keeps that window as short as the protocol allows.
struct ChainSteps<'a> {
    rpc_url: &'a str,
    prover: &'a ProverClient,
    member: &'a Keypair,
    settings: Pubkey,
    account_index: u8,
    tree: Pubkey,
    snapshot: TreeSnapshot,
    applied: u64,
    values: Vec<[u8; 32]>,
    reference: ReferenceNullifierTree,
}

impl DrainSteps for ChainSteps<'_> {
    type Append = ProvedAppend;

    fn prove(&mut self, offset: u64) -> Result<ProvedAppend> {
        let snapshot = &self.snapshot;
        let zkp_index = offset_at(snapshot.already_applied, offset, 1)?;
        let batch_next_index = offset_at(snapshot.next_index, offset, snapshot.zkp_batch_size)?;
        let start = usize::try_from(offset_at(self.applied, offset, snapshot.zkp_batch_size)?)
            .map_err(|_| anyhow!("zkp-batch {zkp_index} start exceeds usize"))?;
        let end =
            start
                .checked_add(usize::try_from(snapshot.zkp_batch_size).map_err(|_| {
                    anyhow!("zkp_batch_size {} exceeds usize", snapshot.zkp_batch_size)
                })?)
                .ok_or_else(|| anyhow!("zkp-batch {zkp_index} end overflows usize"))?;
        let batch_values = self
            .values
            .get(start..end)
            .ok_or_else(|| anyhow!("queued nullifier slice {start}..{end} out of range"))?;
        let hash_chain = snapshot
            .hash_chains
            .get(
                usize::try_from(offset)
                    .map_err(|_| anyhow!("ready zkp-batch index {offset} exceeds usize"))?,
            )
            .copied()
            .ok_or_else(|| anyhow!("missing hash chain for ready zkp-batch {offset}"))?;
        let old_root = self.reference.root();

        let (inputs, new_root) = build_inputs(
            &mut self.reference,
            batch_next_index,
            snapshot.height,
            hash_chain,
            old_root,
            batch_values,
        )?;

        let proof = self
            .prover
            .prove_batch_address_append(&inputs)
            .map_err(|err| anyhow!("prove zkp-batch {zkp_index}: {err}"))?;
        let compressed = ProofCompressed::try_from(proof)
            .map_err(|err| anyhow!("compress proof for zkp-batch {zkp_index}: {err:?}"))?;

        Ok(ProvedAppend {
            zkp_index,
            old_root,
            new_root,
            hash_chain,
            start_index: batch_next_index,
            proof,
            compressed,
        })
    }

    /// Prove one fold over `span` and settle the whole span in one transaction.
    fn submit_fold(&mut self, span: &[ProvedAppend], run: u32) -> Result<(), FoldFailure> {
        let first = span
            .first()
            .ok_or_else(|| FoldFailure::Prove(anyhow!("empty fold span")))?;
        let last = span
            .last()
            .ok_or_else(|| FoldFailure::Prove(anyhow!("empty fold span")))?;
        let batch_size = u32::try_from(self.snapshot.zkp_batch_size).map_err(|_| {
            FoldFailure::Prove(anyhow!(
                "zkp_batch_size {} exceeds u32",
                self.snapshot.zkp_batch_size
            ))
        })?;

        let fold = self
            .prover
            .prove_nullifier_fold(&NullifierFoldInputs {
                tree_height: self.snapshot.height,
                batch_size,
                appends: span
                    .iter()
                    .map(|append| FoldAppend {
                        proof: append.proof,
                        old_root: append.old_root,
                        new_root: append.new_root,
                        hashchain_hash: append.hash_chain,
                        start_index: append.start_index,
                    })
                    .collect(),
            })
            .map_err(|err| {
                FoldFailure::Prove(anyhow!("prove fold over {run} zkp-batches: {err}"))
            })?;
        let compressed = ProofCompressed::try_from(fold)
            .map_err(|err| FoldFailure::Prove(anyhow!("compress fold proof: {err:?}")))?;
        let commitment = compressed
            .commitment
            .ok_or_else(|| FoldFailure::Prove(anyhow!("fold proof carries no BSB22 commitment")))?;

        let signature = batch_update_nullifier_tree_folded_once(
            self.settings,
            self.account_index,
            self.member,
            self.tree,
            self.rpc_url,
            &FoldedRun {
                run,
                old_root: first.old_root,
                new_root: last.new_root,
                proof: CompressedProof {
                    a: compressed.a,
                    b: compressed.b,
                    c: compressed.c,
                },
                commitment: commitment.commitment,
                commitment_pok: commitment.commitment_pok,
            },
        )
        .map_err(|err| FoldFailure::Submit(anyhow!("submit folded run of {run}: {err}")))?;

        tracing::info!(
            %signature,
            run,
            first_zkp_index = first.zkp_index,
            new_root = %hex::encode(last.new_root),
            "submitted folded nullifier run"
        );
        Ok(())
    }

    fn submit_single(&mut self, append: &ProvedAppend) -> Result<()> {
        let zkp_batch_index = u16::try_from(append.zkp_index).map_err(|_| {
            anyhow!(
                "zkp-batch index {} exceeds the on-chain u16",
                append.zkp_index
            )
        })?;
        let signature = batch_update_nullifier_tree_once(ForestParams {
            rpc_url: self.rpc_url,
            member: self.member,
            settings: self.settings,
            account_index: self.account_index,
            pool_tree: self.tree,
            batch_update: BatchUpdateNullifierTreeData {
                new_root: append.new_root,
                old_root: append.old_root,
                zkp_batch_index,
                compressed_proof: CompressedProof {
                    a: append.compressed.a,
                    b: append.compressed.b,
                    c: append.compressed.c,
                },
            },
        })
        .map_err(|err| anyhow!("submit zkp-batch {}: {err}", append.zkp_index))?;

        tracing::info!(%signature, zkp_index = append.zkp_index, new_root = %hex::encode(append.new_root), "submitted nullifier batch update");
        Ok(())
    }
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
/// values into `reference`.
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

    let batch_size = u32::try_from(batch_values.len())
        .map_err(|_| anyhow!("zkp-batch of {} values exceeds u32", batch_values.len()))?;
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
            batch_size,
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

    /// A run folds only at the configured width, and the tail that has no key
    /// still submits. Folding at any other width would need a key that does not
    /// exist, so the plan must never produce one.
    #[test]
    fn fold_span_folds_only_at_the_configured_width() {
        assert_eq!(fold_span(5, None), None, "unset means submit one at a time");
        assert_eq!(fold_span(1, Some(2)), None, "a short tail cannot fold");
        assert_eq!(fold_span(2, Some(2)), Some(2));
        assert_eq!(
            fold_span(5, Some(2)),
            Some(2),
            "folds a prefix, leaves the rest"
        );
        assert_eq!(
            fold_span(5, Some(1)),
            None,
            "a run of one does not amortize"
        );
        assert_eq!(fold_span(5, Some(0)), None);
    }

    #[test]
    fn only_on_chain_fold_configuration_is_supported() {
        assert!(is_supported_batch_address_fold(40, 10, 2));
        assert!(!is_supported_batch_address_fold(40, 10, 3));
        assert!(!is_supported_batch_address_fold(40, 250, 2));
        assert!(!is_supported_batch_address_fold(32, 10, 2));
    }

    /// The prove and submit side of a pass, driven by a plan instead of a
    /// prover and a validator.
    #[derive(Default)]
    struct FakeSteps {
        proved: Vec<u64>,
        singles: Vec<u64>,
        /// `(first offset, run)` per folded transaction.
        folds: Vec<(u64, u32)>,
        prove_fails_at: Option<u64>,
        fold_prove_fails: bool,
        fold_submit_fails: bool,
        single_fails_at: Option<u64>,
    }

    impl DrainSteps for FakeSteps {
        type Append = u64;

        fn prove(&mut self, offset: u64) -> Result<u64> {
            if self.prove_fails_at == Some(offset) {
                bail!("prover restarted while proving {offset}");
            }
            self.proved.push(offset);
            Ok(offset)
        }

        fn submit_fold(&mut self, span: &[u64], run: u32) -> Result<(), FoldFailure> {
            if self.fold_prove_fails {
                return Err(FoldFailure::Prove(anyhow!("fold prover out of memory")));
            }
            if self.fold_submit_fails {
                return Err(FoldFailure::Submit(anyhow!("old_root is stale")));
            }
            let first = *span
                .first()
                .ok_or_else(|| FoldFailure::Prove(anyhow!("empty fold span")))?;
            self.folds.push((first, run));
            Ok(())
        }

        fn submit_single(&mut self, append: &u64) -> Result<()> {
            if self.single_fails_at == Some(*append) {
                bail!("transaction for {append} failed");
            }
            self.singles.push(*append);
            Ok(())
        }
    }

    /// Five ready batches at width two must land as two folds plus one single,
    /// which is three transactions against five today.
    #[test]
    fn a_run_of_five_folds_into_two_spans_and_a_single() {
        let mut steps = FakeSteps::default();

        let progress = drive_pass(&mut steps, 5, Some(2));

        assert_eq!(progress.submitted, 5);
        assert!(progress.stalled.is_none());
        assert_eq!(steps.folds, vec![(0, 2), (2, 2)]);
        assert_eq!(steps.singles, vec![4]);
    }

    /// A proving failure must not throw away the proofs that already landed on
    /// chain before it.
    #[test]
    fn a_prove_failure_keeps_everything_submitted_before_it() {
        let mut steps = FakeSteps {
            prove_fails_at: Some(3),
            ..Default::default()
        };

        let progress = drive_pass(&mut steps, 5, None);

        assert_eq!(progress.submitted, 3);
        assert!(
            progress.stalled.is_some(),
            "the pass reports a partial drain"
        );
        assert_eq!(steps.singles, vec![0, 1, 2]);
    }

    /// Proving stops midway through a fold span. The span cannot fold at a
    /// width with no key, so its proved appends still submit one at a time.
    #[test]
    fn a_half_proved_fold_span_submits_its_appends_singly() {
        let mut steps = FakeSteps {
            prove_fails_at: Some(3),
            ..Default::default()
        };

        let progress = drive_pass(&mut steps, 6, Some(2));

        assert_eq!(progress.submitted, 3);
        assert!(progress.stalled.is_some());
        assert_eq!(steps.folds, vec![(0, 2)]);
        assert_eq!(steps.singles, vec![2]);
    }

    /// The single appends are proved before the fold is, so a failed fold proof
    /// costs a transaction, not the pass.
    #[test]
    fn a_fold_prover_failure_falls_back_to_single_appends() {
        let mut steps = FakeSteps {
            fold_prove_fails: true,
            ..Default::default()
        };

        let progress = drive_pass(&mut steps, 4, Some(2));

        assert_eq!(progress.submitted, 4);
        assert!(progress.stalled.is_none());
        assert!(steps.folds.is_empty());
        assert_eq!(steps.singles, vec![0, 1, 2, 3]);
    }

    #[test]
    fn a_failed_folded_transaction_stops_the_pass() {
        let mut steps = FakeSteps {
            fold_submit_fails: true,
            ..Default::default()
        };

        let progress = drive_pass(&mut steps, 4, Some(2));

        assert_eq!(progress.submitted, 0);
        assert!(progress.stalled.is_some());
        assert!(
            steps.singles.is_empty(),
            "a folded transaction can still land after the client stops waiting, so the span must not be submitted again"
        );
    }

    #[test]
    fn a_failed_submission_stops_the_pass() {
        let mut steps = FakeSteps {
            single_fails_at: Some(2),
            ..Default::default()
        };

        let progress = drive_pass(&mut steps, 5, None);

        assert_eq!(progress.submitted, 2);
        assert!(progress.stalled.is_some());
        assert_eq!(
            steps.proved,
            vec![0, 1, 2],
            "the root did not move, so the pass stops proving against it"
        );
    }

    fn drained(submitted: u64) -> Result<DrainOutcome> {
        Ok(DrainOutcome::Drained(PassProgress {
            submitted,
            stalled: None,
        }))
    }

    fn stalled(submitted: u64) -> Result<DrainOutcome> {
        Ok(DrainOutcome::Drained(PassProgress {
            submitted,
            stalled: Some(anyhow!("prover restarted")),
        }))
    }

    #[test]
    fn the_watch_loop_retries_the_rest_after_a_stalled_pass() {
        let mut passes = vec![stalled(1), stalled(0), drained(3)].into_iter();
        let mut waits = Vec::new();

        let submitted_total = WatchLoop {
            watch: true,
            poll_secs: 7,
            max_batches: Some(4),
        }
        .drive(
            |_| {
                passes
                    .next()
                    .expect("the loop ran more passes than planned")
            },
            |delay| waits.push(delay),
        )
        .unwrap();

        assert_eq!(submitted_total, 4);
        assert_eq!(
            waits,
            vec![Duration::from_secs(7)],
            "only the pass that landed nothing waits"
        );
        assert!(passes.next().is_none());
    }

    #[test]
    fn the_watch_loop_retries_a_lagging_indexer() {
        let mut passes = vec![
            Ok(DrainOutcome::NotReady(PhotonIndexNotReady::new(
                1, 2, "lag",
            ))),
            drained(2),
        ]
        .into_iter();
        let mut waits = Vec::new();

        let submitted_total = WatchLoop {
            watch: true,
            poll_secs: 3,
            max_batches: Some(2),
        }
        .drive(
            |_| {
                passes
                    .next()
                    .expect("the loop ran more passes than planned")
            },
            |delay| waits.push(delay),
        )
        .unwrap();

        assert_eq!(submitted_total, 2);
        assert_eq!(waits, vec![Duration::from_secs(3)]);
    }

    /// Without `--watch` nothing retries the remainder, so the stall is the
    /// exit status even though part of the pass landed.
    #[test]
    fn a_single_run_reports_a_stalled_pass_as_an_error() {
        let error = WatchLoop {
            watch: false,
            poll_secs: 1,
            max_batches: None,
        }
        .drive(|_| stalled(2), |_| panic!("a single pass must not wait"))
        .unwrap_err();

        assert!(error.to_string().contains("prover restarted"));
    }

    #[test]
    fn the_cap_shrinks_by_what_earlier_passes_submitted() {
        let mut limits = Vec::new();
        let mut passes = vec![drained(2), drained(3)].into_iter();

        let submitted_total = WatchLoop {
            watch: true,
            poll_secs: 1,
            max_batches: Some(5),
        }
        .drive(
            |limit| {
                limits.push(limit);
                passes
                    .next()
                    .expect("the loop ran more passes than planned")
            },
            |_| panic!("a pass that submits must not wait"),
        )
        .unwrap();

        assert_eq!(submitted_total, 5);
        assert_eq!(limits, vec![Some(5), Some(3)]);
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
                (0, PAGE_LIMIT),
                (PAGE_LIMIT, PAGE_LIMIT),
                (PAGE_LIMIT * 2, 7)
            ]
        );
        assert_eq!(values.len(), usize::try_from(total).unwrap());
        assert_eq!(values.last().unwrap()[24..], (total - 1).to_be_bytes());
    }

    #[test]
    fn empty_nullifier_fetch_skips_photon() {
        let values = collect_nullifier_pages(0, |_, _| {
            panic!("an empty prefix must not issue a Photon request")
        })
        .unwrap();
        assert!(values.is_empty());
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
