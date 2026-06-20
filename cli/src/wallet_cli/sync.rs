use std::thread::sleep;
use std::time::SystemTime;

use anyhow::{bail, Result};
use solana_signature::Signature;
use zolana_client::{sync_wallet as client_sync_wallet, Rpc, SolanaRpc, ZolanaIndexer};
use zolana_transaction::{AssetRegistry, Wallet};

use crate::args::SyncOptions;

use super::material::{clone_keypair, load_sender_from_sync, WalletMaterial};
use super::{INDEXER_POLL, INDEXER_TIMEOUT};

pub(super) struct SyncContext {
    pub(super) material: WalletMaterial,
    pub(super) wallet: Wallet,
    pub(super) assets: AssetRegistry,
    pub(super) report: zolana_transaction::SyncReport,
}

pub(super) fn run_sync(opts: SyncOptions) -> Result<()> {
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
    let material = load_sender_from_sync(opts)?;
    let rpc = SolanaRpc::new(opts.rpc_url.clone());
    let indexer = ZolanaIndexer::new(opts.indexer_url.clone());
    let assets = AssetRegistry::default();
    let mut wallet = Wallet::new(clone_keypair(&material.keypair)?)?;
    let report = client_sync_wallet(&mut wallet, &indexer, &rpc, &assets)?;
    Ok(SyncContext {
        material,
        wallet,
        assets,
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

pub(super) fn wait_for_indexed_transaction(
    indexer: &ZolanaIndexer,
    tag: [u8; 32],
    signature: Signature,
) -> Result<()> {
    let started = SystemTime::now();
    loop {
        let response = indexer.get_shielded_transactions_by_tags(vec![tag], None, Some(50))?;
        if response
            .transactions
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
