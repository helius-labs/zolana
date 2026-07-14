use std::{thread::sleep, time::SystemTime};

use anyhow::{bail, Result};
use solana_signature::Signature;
use zolana_client::{sync_wallet as client_sync_wallet, Rpc, ZolanaIndexer};
use zolana_transaction::Wallet;

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
    let config = CliConfigFile::load()?;
    let sync = resolve_sync_with_config(opts, &config)?;
    let material = load_sender_from_resolved_sync(&sync)?;
    let indexer = ZolanaIndexer::new(sync.indexer_url.clone());
    let assets = config.local_asset_registry()?;
    let mut wallet = Wallet::new(material.keypair.shielded_address()?, assets)?;
    let report = client_sync_wallet(&mut wallet, &material, &indexer)?;
    Ok(SyncContext {
        material,
        wallet,
        local_assets: config.assets,
        report,
    })
}

pub(super) fn wait_for_indexed_utxo(
    indexer: &ZolanaIndexer,
    tag: [u8; 32],
    signature: Signature,
) -> Result<()> {
    let started = SystemTime::now();
    loop {
        let response = indexer.get_encrypted_utxos_by_tags(vec![tag], None, Some(50))?;
        if response
            .matches
            .iter()
            .any(|item| item.tx_signature == signature)
        {
            return Ok(());
        }
        if started.elapsed().unwrap_or_default() >= INDEXER_TIMEOUT {
            bail!("timed out waiting for Photon to index {signature}");
        }
        sleep(INDEXER_POLL);
    }
}
