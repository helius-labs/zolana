use anyhow::{Context, Result};
use solana_signature::Signature;
use zolana_client::{IndexerPollConfig, Rpc, ZolanaIndexer};
use zolana_transaction::{Address, Wallet};
use zolana_wallet::{
    sync_wallet_with_config as client_sync_wallet_with_config, SyncWalletConfig,
};

use super::{
    material::{load_sender_from_resolved_sync, WalletMaterial},
    resolve::resolve_sync_with_config,
    INDEXER_POLL, INDEXER_TIMEOUT,
};
use crate::{
    args::SyncOptions,
    cli_config::{CliConfigFile, LocalAssetConfig},
};

pub(super) struct SyncContext {
    pub(super) material: WalletMaterial,
    pub(super) wallet: Wallet,
    pub(super) local_assets: Vec<LocalAssetConfig>,
    pub(super) report: zolana_transaction::SyncReport,
}

pub(crate) fn run_sync(opts: SyncOptions) -> Result<()> {
    let ctx = sync_context(&opts)?;
    println!(
        "ok sync stored={} unparsed={} undecryptable={}",
        ctx.report.stored_utxos,
        ctx.report.unparsed_transactions,
        ctx.report.undecryptable_candidates
    );
    Ok(())
}

pub(super) fn sync_context(opts: &SyncOptions) -> Result<SyncContext> {
    sync_context_inner(opts, SyncWalletConfig::new())
}

/// Sync with a slot-based freshness gate: the indexer must have persisted the
/// chain's current slot, read from the same RPC this CLI submits through, before
/// its answers are accepted.
///
/// This is the sound form of the wait. The fallback it replaces compares the
/// indexer's block timestamp against local wall clock, which mixes clock domains
/// and cannot be satisfied while block time trails real time — costing ~2.5s of
/// backoff on every gated call regardless of how current the indexer is.
pub(super) fn sync_context_at_current_slot(
    opts: &SyncOptions,
    rpc: &dyn Rpc,
) -> Result<SyncContext> {
    let target_slot = rpc.get_slot().context("fetching current slot")?;
    sync_context_inner(
        opts,
        SyncWalletConfig {
            target_slot: Some(target_slot),
            ..SyncWalletConfig::new()
        },
    )
}

/// Sync for read-only display commands (`balance`, `utxos`).
///
/// Uses `SyncWalletConfig::default()`, which leaves `wait_for_indexer` off, where
/// `new()` turns it on. That gate exists so a command can read back state it just
/// wrote; these commands write nothing, so there is nothing to read back and the
/// wait is pure latency — it costs ~2.5s per invocation because it blocks until
/// photon reports a block timestamp past the local wall clock at request time.
///
/// Commands that submit transactions keep the gate, and confirm their own writes
/// precisely via `wait_for_indexed_utxo` / `wait_for_indexed_leaf`.
pub(super) fn sync_context_read_only(opts: &SyncOptions) -> Result<SyncContext> {
    sync_context_inner(opts, SyncWalletConfig::default())
}

fn sync_context_inner(opts: &SyncOptions, sync_config: SyncWalletConfig) -> Result<SyncContext> {
    let config = CliConfigFile::load()?;
    let sync = resolve_sync_with_config(opts, &config)?;
    let material = load_sender_from_resolved_sync(&sync)?;
    let indexer = ZolanaIndexer::new(sync.indexer_url.clone());
    let assets = config.local_asset_registry()?;
    let mut wallet = Wallet::new(material.keypair.shielded_address()?, assets)?;
    let report = client_sync_wallet_with_config(&mut wallet, &material, &indexer, sync_config)?;
    Ok(SyncContext {
        material,
        wallet,
        local_assets: config.assets,
        report,
    })
}

/// The CLI's indexer poll schedule: [`INDEXER_POLL`] between attempts (constant,
/// no backoff growth) for a total budget of [`INDEXER_TIMEOUT`].
fn indexer_poll() -> IndexerPollConfig {
    let delay_ms = INDEXER_POLL.as_millis() as u64;
    let retries = (INDEXER_TIMEOUT.as_millis() / INDEXER_POLL.as_millis().max(1)) as u32;
    IndexerPollConfig::new(retries, delay_ms, delay_ms)
}

pub(super) fn wait_for_indexed_utxo(
    indexer: &ZolanaIndexer,
    tag: [u8; 32],
    signature: Signature,
) -> Result<()> {
    indexer_poll()
        .poll_until(
            || indexer.get_encrypted_utxos_by_tags(vec![tag], None, Some(50), None),
            |response| {
                response
                    .matches
                    .iter()
                    .any(|item| item.tx_signature == signature)
            },
        )
        .with_context(|| format!("timed out waiting for Photon to index {signature}"))?;
    Ok(())
}

/// Poll the indexer until `leaf` is present in `tree`. Merge's `merge_transact`
/// output is not on the view-tag confirmation path a transfer uses, so a caller
/// that reads the consolidated note back immediately must wait for its state leaf
/// to be appended.
pub(super) fn wait_for_indexed_leaf<R: Rpc>(rpc: &R, tree: Address, leaf: [u8; 32]) -> Result<()> {
    indexer_poll()
        .poll_until(
            || rpc.get_merkle_proofs(tree, vec![leaf], None),
            |response| {
                response
                    .proofs
                    .iter()
                    .any(|proof| proof.leaf == leaf && proof.merkle_context.tree == tree)
            },
        )
        .context("timed out waiting for Photon to index leaf")?;
    Ok(())
}
