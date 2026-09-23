use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use solana_signature::Signature;
use zolana_client::{EncryptedUtxoMatch, IndexerPollConfig, Rpc, ZolanaIndexer};
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{
    Address, AssetRegistry, ShieldedTransaction, SyncReport, Wallet, DEFAULT_TAG_WINDOW,
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

const PAGE_LIMIT: u32 = 1_000;

pub(super) struct SyncContext {
    pub(super) material: WalletMaterial,
    pub(super) wallet: Wallet,
    pub(super) local_assets: Vec<LocalAssetConfig>,
    pub(super) report: SyncReport,
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

/// Rounds of nullifier queries: each can reveal change whose own spend is
/// then queried.
const SPEND_ROUNDS: usize = 6;

/// Fetch every default-ring transaction of the wallet and decrypt it.
///
/// The CLI's notes all live on the default ring: transfers to it, its own
/// change, splits and merges are tagged with its owner tag, and deposits with
/// its viewing key or its owner tag. A spend another client made may carry neither, so the
/// unspent notes' nullifiers are queried until no new transaction appears.
/// Anonymous transfers, tagged per counterparty, are not read.
pub(super) fn sync_context(opts: &SyncOptions) -> Result<SyncContext> {
    let config = CliConfigFile::load()?;
    let sync = resolve_sync_with_config(opts, &config)?;
    let material = load_sender_from_resolved_sync(&sync)?;
    let indexer = ZolanaIndexer::new(sync.indexer_url.clone());
    let assets = config.local_asset_registry()?;
    let mut transactions = wallet_transactions(&indexer, &material.keypair)?;
    let (mut wallet, mut report) = scan(&material, &assets, &transactions)?;
    for _ in 0..SPEND_ROUNDS {
        let nullifiers: Vec<[u8; 32]> = wallet.unspent().map(|entry| entry.nullifier).collect();
        let before = transactions.len();
        transactions.extend(spending_transactions(&indexer, nullifiers)?);
        if transactions.len() == before {
            break;
        }
        (wallet, report) = scan(&material, &assets, &transactions)?;
    }
    Ok(SyncContext {
        material,
        wallet,
        local_assets: config.assets,
        report,
    })
}

/// Keyed by signature, and for a proofless deposit also by the leaf its one
/// output landed at: one deposit transaction can shield several outputs.
type Transactions = HashMap<(Signature, Option<u64>), ShieldedTransaction>;

/// A fresh wallet over `transactions`, so the report counts all of them.
fn scan(
    material: &WalletMaterial,
    assets: &AssetRegistry,
    transactions: &Transactions,
) -> Result<(Wallet, SyncReport)> {
    // Transactions in chain order, then deposits in tree order.
    let mut ordered: Vec<ShieldedTransaction> = transactions.values().cloned().collect();
    ordered.sort_by_key(|tx| {
        let leaf = tx.proofless.then(|| {
            let context = &tx.output_slots[0].output_context;
            (context.tree_id, context.leaf_index)
        });
        (tx.proofless, leaf, tx.slot, tx.tx_signature)
    });
    let mut wallet = Wallet::new(material.keypair.shielded_address()?, assets.clone())?;
    let report = wallet.sync(material, &ordered, now(), DEFAULT_TAG_WINDOW)?;
    Ok((wallet, report))
}

/// The shielded transactions tagged for `keypair`, and its proofless deposits.
/// A payer who knows only the viewing key tags with it.
fn wallet_transactions(indexer: &ZolanaIndexer, keypair: &ShieldedKeypair) -> Result<Transactions> {
    let owner_tag = keypair
        .shielded_address()?
        .signing_pubkey
        .confidential_view_tag()?;
    let deposit_tag = keypair.viewing_key.recipient_bootstrap_view_tag();
    let mut transactions = Transactions::new();
    let mut cursor = None;
    loop {
        let page = indexer.get_shielded_transactions_by_tags(
            vec![owner_tag, deposit_tag],
            cursor,
            Some(PAGE_LIMIT),
            None,
        )?;
        // Deposits come from the encrypted-utxo stream below, one per output.
        for tx in page.transactions.into_iter().filter(|tx| !tx.proofless) {
            transactions.insert((tx.tx_signature, None), tx);
        }
        let Some(next) = page.next_cursor else { break };
        cursor = Some(next);
    }
    let mut cursor = None;
    loop {
        let page = indexer.get_encrypted_utxos_by_tags(
            vec![owner_tag, deposit_tag],
            cursor,
            Some(PAGE_LIMIT),
            None,
        )?;
        for tx in page
            .matches
            .into_iter()
            .filter_map(EncryptedUtxoMatch::into_proofless_transaction)
        {
            let leaf = tx.output_slots[0].output_context.leaf_index;
            transactions.insert((tx.tx_signature, Some(leaf)), tx);
        }
        let Some(next) = page.next_cursor else { break };
        cursor = Some(next);
    }
    Ok(transactions)
}

/// The transactions that spent any of `nullifiers`.
fn spending_transactions(
    indexer: &ZolanaIndexer,
    nullifiers: Vec<[u8; 32]>,
) -> Result<Transactions> {
    let mut transactions = Transactions::new();
    for chunk in nullifiers.chunks(PAGE_LIMIT as usize) {
        let mut cursor = None;
        loop {
            let page = indexer.get_shielded_transactions_by_nullifiers(
                chunk.to_vec(),
                cursor,
                Some(PAGE_LIMIT),
                None,
            )?;
            for tx in page.transactions {
                transactions.insert((tx.tx_signature, None), tx);
            }
            let Some(next) = page.next_cursor else { break };
            cursor = Some(next);
        }
    }
    Ok(transactions)
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64)
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
