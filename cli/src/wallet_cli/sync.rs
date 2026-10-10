use anyhow::{Context, Result};
use solana_signature::Signature;
use zolana_client::{
    EncryptedUtxoMatch, IndexerPollConfig, IndexerRpcConfig, Rpc, SolanaRpc, SpendableUtxos,
    ZolanaIndexer,
};
use zolana_transaction::SpendableDecryptionResult;

use super::{
    material::{load_sender_from_resolved_sync, WalletMaterial},
    resolve::{resolve_sync, resolve_sync_with_config},
    util::format_address,
    INDEXER_POLL, INDEXER_TIMEOUT,
};
use crate::{
    args::SyncOptions,
    cli_config::{CliConfigFile, LocalAssetConfig},
};

pub(super) struct SyncContext {
    pub(super) material: WalletMaterial,
    pub(super) spendable: SpendableDecryptionResult,
    pub(super) local_assets: Vec<LocalAssetConfig>,
}

pub(crate) fn run_sync(opts: SyncOptions) -> Result<()> {
    let ctx = sync_context(&opts, &sync_rpc(&opts)?)?;
    println!("ok sync utxos={}", ctx.spendable.utxos().count());
    // UTXOs in these assets are left out until the asset is in the local
    // asset config.
    for asset_id in &ctx.spendable.unknown_asset_ids {
        println!("warn sync unregistered_asset_id={asset_id}");
    }
    for mint in &ctx.spendable.unknown_mints {
        println!("warn sync unregistered_mint={}", format_address(*mint));
    }
    Ok(())
}

/// The wallet's spendable UTXOs, read afresh from an indexer caught up with the
/// RPC, so a spend another client just made is not selected again. The CLI's UTXOs
/// all live on the default ring and carry its owner tag or, as deposits, its
/// viewing key's tag. Anonymous transfers, tagged per counterparty, are not
/// read; no CLI command produces them.
pub(super) fn sync_context(opts: &SyncOptions, rpc: &SolanaRpc) -> Result<SyncContext> {
    let config = CliConfigFile::load()?;
    let sync = resolve_sync_with_config(opts, &config)?;
    let material = load_sender_from_resolved_sync(&sync)?;
    let indexer = ZolanaIndexer::new(sync.indexer_url.clone());
    let assets = config.local_asset_registry()?;
    let slot = rpc.get_slot()?;
    let spendable = SpendableUtxos::new(&material.keypair, &assets)
        .with_indexer_config(IndexerRpcConfig {
            poll: indexer_poll(),
            require_slot: Some(slot),
        })
        .fetch(&indexer)?;
    Ok(SyncContext {
        material,
        spendable,
        local_assets: config.assets,
    })
}

/// The RPC of a command that reads the wallet without sending.
pub(super) fn sync_rpc(opts: &SyncOptions) -> Result<SolanaRpc> {
    Ok(SolanaRpc::new(resolve_sync(opts)?.rpc_url))
}

/// The CLI's indexer poll schedule: [`INDEXER_POLL`] between attempts (constant,
/// no backoff growth) for a total budget of [`INDEXER_TIMEOUT`].
fn indexer_poll() -> IndexerPollConfig {
    let delay_ms = INDEXER_POLL.as_millis() as u64;
    let retries = (INDEXER_TIMEOUT.as_millis() / INDEXER_POLL.as_millis().max(1)) as u32;
    IndexerPollConfig::new(retries, delay_ms, delay_ms)
}

/// Polls until Photon serves the output `signature` created under `tag`, and
/// returns that match. A proofless deposit publishes its blinding and UTXO hash
/// in the clear, so the indexed match identifies the deposited UTXO.
pub(super) fn wait_for_indexed_utxo(
    indexer: &ZolanaIndexer,
    tag: [u8; 32],
    signature: Signature,
) -> Result<EncryptedUtxoMatch> {
    let response = indexer_poll()
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
    response
        .matches
        .into_iter()
        .find(|item| item.tx_signature == signature)
        .with_context(|| format!("Photon returned no indexed output for {signature}"))
}
