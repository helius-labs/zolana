use std::collections::{HashMap, HashSet};
use std::thread::sleep;
use std::time::SystemTime;

use anyhow::{bail, Result};
use solana_signature::Signature;
use zolana_client::{Rpc, ShieldedTransaction, SolanaRpc, ZolanaIndexer};
use zolana_interface::event::{
    indexed_events_from_instruction_groups, proofless_output, DepositView,
};
use zolana_interface::PROGRAM_ID_PUBKEY;
use zolana_transaction::transfer::OutputCiphertext;
use zolana_transaction::{AssetRegistry, SyncTransaction, Wallet, DEFAULT_TAG_WINDOW, TRANSFER};

use crate::args::SyncOptions;

use super::material::{clone_keypair, load_sender_from_sync, WalletMaterial};
use super::util::now_unix_ts;
use super::{INDEXER_POLL, INDEXER_TIMEOUT, QUERY_LIMIT, SYNC_ROUNDS, TAG_QUERY_CHUNK};

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
    let (wallet, report) = sync_wallet(&material, &rpc, &indexer, &assets)?;
    Ok(SyncContext {
        material,
        wallet,
        assets,
        report,
    })
}

fn sync_wallet(
    material: &WalletMaterial,
    rpc: &SolanaRpc,
    indexer: &ZolanaIndexer,
    assets: &AssetRegistry,
) -> Result<(Wallet, zolana_transaction::SyncReport)> {
    let mut wallet = Wallet::new(clone_keypair(&material.keypair)?)?;
    let mut transactions: HashMap<String, SyncTransaction> = HashMap::new();
    let mut proofless_deposits: HashMap<String, DepositView> = HashMap::new();
    let mut report = zolana_transaction::SyncReport::default();

    for _ in 0..SYNC_ROUNDS {
        let before = (transactions.len(), proofless_deposits.len());
        let tags = wallet_query_tags(&wallet)?;
        fetch_shielded_transactions(indexer, &tags, &mut transactions)?;
        fetch_proofless_deposits(rpc, indexer, &tags, &mut proofless_deposits)?;

        let mut txs = transactions.values().cloned().collect::<Vec<_>>();
        txs.sort_by_key(|tx| tx.nullifiers.first().copied().unwrap_or_default());
        let mut deposits = proofless_deposits.values().cloned().collect::<Vec<_>>();
        deposits.sort_by_key(|deposit| (deposit.output_tree, deposit.leaf_index));
        report = wallet.sync(&txs, &deposits, assets, now_unix_ts(), DEFAULT_TAG_WINDOW)?;

        if before == (transactions.len(), proofless_deposits.len()) {
            break;
        }
    }

    Ok((wallet, report))
}

fn wallet_query_tags(wallet: &Wallet) -> Result<Vec<[u8; 32]>> {
    let mut tags = HashSet::new();
    for entry in &wallet.viewing_key_history {
        tags.insert(entry.key.recipient_bootstrap_view_tag());
        for n in 0..entry.tx_count.saturating_add(DEFAULT_TAG_WINDOW) {
            tags.insert(entry.key.get_sender_view_tag(n)?);
        }
        for n in 0..entry.request_count.saturating_add(DEFAULT_TAG_WINDOW) {
            tags.insert(entry.key.get_recipient_request_view_tag(n)?);
        }
        for (sender, count) in &entry.known_senders {
            for n in 0..count.saturating_add(DEFAULT_TAG_WINDOW) {
                tags.insert(entry.key.get_recipient_shared_view_tag(sender, n)?);
            }
        }
        for (recipient, count) in &entry.known_recipients {
            for n in 0..count.saturating_add(DEFAULT_TAG_WINDOW) {
                tags.insert(entry.key.get_send_shared_view_tag(recipient, n)?);
            }
        }
    }
    Ok(tags.into_iter().collect())
}

fn fetch_shielded_transactions(
    indexer: &ZolanaIndexer,
    tags: &[[u8; 32]],
    out: &mut HashMap<String, SyncTransaction>,
) -> Result<()> {
    for chunk in tags.chunks(TAG_QUERY_CHUNK) {
        let mut cursor = None;
        loop {
            let response = indexer.get_shielded_transactions_by_tags(
                chunk.to_vec(),
                cursor,
                Some(QUERY_LIMIT),
            )?;
            for tx in response.transactions {
                if tx.proofless {
                    continue;
                }
                let key = tx.tx_signature.to_string();
                out.entry(key).or_insert(convert_sync_transaction(tx)?);
            }
            cursor = response.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
    }
    Ok(())
}

fn fetch_proofless_deposits(
    rpc: &SolanaRpc,
    indexer: &ZolanaIndexer,
    tags: &[[u8; 32]],
    out: &mut HashMap<String, DepositView>,
) -> Result<()> {
    for chunk in tags.chunks(TAG_QUERY_CHUNK) {
        let mut cursor = None;
        loop {
            let response =
                indexer.get_encrypted_utxos_by_tags(chunk.to_vec(), cursor, Some(QUERY_LIMIT))?;
            for item in response.matches {
                if item.tx_viewing_pk.is_some() {
                    continue;
                }
                let key = item.tx_signature.to_string();
                if out.contains_key(&key) {
                    continue;
                }
                if let Some(view) =
                    proofless_deposit_from_signature(rpc, item.tx_signature, item.view_tag)?
                {
                    out.insert(key, view);
                }
            }
            cursor = response.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
    }
    Ok(())
}

fn convert_sync_transaction(tx: ShieldedTransaction) -> Result<SyncTransaction> {
    let tx_viewing_pk = tx
        .tx_viewing_pk
        .ok_or_else(|| anyhow::anyhow!("indexed transaction missing tx_viewing_pk"))?;
    let salt = tx
        .salt
        .ok_or_else(|| anyhow::anyhow!("indexed transaction missing salt"))?;
    Ok(SyncTransaction {
        scheme: TRANSFER,
        tx_viewing_pk,
        salt,
        output_slots: tx
            .output_slots
            .into_iter()
            .map(|slot| OutputCiphertext {
                view_tag: slot.view_tag,
                data: slot.payload,
            })
            .collect(),
        nullifiers: tx.nullifiers,
    })
}

fn proofless_deposit_from_signature(
    rpc: &SolanaRpc,
    signature: Signature,
    view_tag: [u8; 32],
) -> Result<Option<DepositView>> {
    let groups = rpc.fetch_confirmed_instruction_groups(&signature)?.groups;
    let events = indexed_events_from_instruction_groups(PROGRAM_ID_PUBKEY, &groups);
    for event in events {
        let Ok(general) = event.decoded else {
            continue;
        };
        let Ok(view) = proofless_output(&general) else {
            continue;
        };
        if view.view_tag == view_tag {
            return Ok(Some(view));
        }
    }
    Ok(None)
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
