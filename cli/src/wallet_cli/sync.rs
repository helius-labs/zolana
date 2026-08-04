use anyhow::{Context, Result};
use solana_signature::Signature;
use zolana_client::{IndexerPollConfig, Rpc, ZolanaIndexer};
use zolana_transaction::{Address, Wallet};
use zolana_wallet::{sync_wallet_with_config as client_sync_wallet_with_config, SyncWalletConfig};

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

/// Sync the wallet from the indexer. One entry point, no freshness gate.
///
/// Every write command already waits for its OWN write to be indexed before it
/// returns — `confirm_private_transaction_sync` does
/// `wait_for_rpc_confirmation` then `wait_for_indexed_transaction(signature)`, and
/// merge additionally waits for its state leaf. Those waits are precise: they name
/// the exact signature or leaf being awaited.
///
/// So by the time any later command reads, the earlier write is already in the
/// index, and a blanket "is the indexer current?" gate ahead of the read protects
/// nothing. It only added latency: the gate cost 2.5-5s per command, which is where
/// `zolana utxos` spent 33.8 of its 33.9 seconds.
///
/// `SyncWalletConfig` still carries `target_slot` for library consumers that need
/// read-your-writes without tracking a signature — that path is sound now that the
/// indexer reports its persisted slot. The CLI simply does not need it.
pub(super) fn sync_context(opts: &SyncOptions) -> Result<SyncContext> {
    let config = CliConfigFile::load()?;
    let sync = resolve_sync_with_config(opts, &config)?;
    let material = load_sender_from_resolved_sync(&sync)?;
    let indexer = ZolanaIndexer::new(sync.indexer_url.clone());
    let assets = config.local_asset_registry()?;
    let mut wallet = Wallet::new(material.keypair.shielded_address()?, assets)?;
    let report = client_sync_wallet_with_config(
        &mut wallet,
        &material,
        &indexer,
        SyncWalletConfig::default(),
    )?;
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
