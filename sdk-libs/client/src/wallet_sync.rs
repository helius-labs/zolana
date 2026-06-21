use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

use solana_signature::Signature;
use zolana_interface::event::DepositView;
use zolana_keypair::viewing_key::ViewTag;
use zolana_transaction::{
    transfer::OutputCiphertext, AssetRegistry, SyncReport, SyncTransaction, Wallet,
    DEFAULT_TAG_WINDOW,
};

use crate::{
    error::ClientError,
    rpc::{Rpc, ShieldedTransaction},
};

const DEFAULT_TAG_QUERY_CHUNK: usize = 64;
const DEFAULT_PAGE_LIMIT: u32 = 1_000;
const DEFAULT_SYNC_ROUNDS: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncWalletConfig {
    pub tag_window: u64,
    pub tag_query_chunk: usize,
    pub page_limit: u32,
    pub rounds: usize,
}

impl Default for SyncWalletConfig {
    fn default() -> Self {
        Self {
            tag_window: DEFAULT_TAG_WINDOW,
            tag_query_chunk: DEFAULT_TAG_QUERY_CHUNK,
            page_limit: DEFAULT_PAGE_LIMIT,
            rounds: DEFAULT_SYNC_ROUNDS,
        }
    }
}

/// Source of decoded proofless deposit events referenced by the indexer.
pub trait ProoflessDepositEventSource {
    fn proofless_deposit_from_signature(
        &self,
        signature: Signature,
        view_tag: ViewTag,
    ) -> Result<Option<DepositView>, ClientError>;
}

pub fn sync_wallet<I, E>(
    wallet: &mut Wallet,
    indexer: &I,
    event_source: &E,
    assets: &AssetRegistry,
) -> Result<SyncReport, ClientError>
where
    I: Rpc,
    E: ProoflessDepositEventSource,
{
    sync_wallet_with_config(
        wallet,
        indexer,
        event_source,
        assets,
        SyncWalletConfig::default(),
    )
}

pub fn sync_wallet_with_config<I, E>(
    wallet: &mut Wallet,
    indexer: &I,
    event_source: &E,
    assets: &AssetRegistry,
    config: SyncWalletConfig,
) -> Result<SyncReport, ClientError>
where
    I: Rpc,
    E: ProoflessDepositEventSource,
{
    let config = normalized_config(config);
    let mut transactions: HashMap<String, SyncTransaction> = HashMap::new();
    let mut proofless_deposits: HashMap<String, DepositView> = HashMap::new();
    let mut report = SyncReport::default();

    for _ in 0..config.rounds {
        let before = (transactions.len(), proofless_deposits.len());
        let tags = wallet_query_tags(wallet, config.tag_window)?;
        fetch_shielded_transactions(indexer, &tags, &mut transactions, config)?;
        fetch_proofless_deposits(
            indexer,
            event_source,
            &tags,
            &mut proofless_deposits,
            config,
        )?;

        let mut txs = transactions.values().cloned().collect::<Vec<_>>();
        txs.sort_by_key(|tx| tx.nullifiers.first().copied().unwrap_or_default());
        let mut deposits = proofless_deposits.values().cloned().collect::<Vec<_>>();
        deposits.sort_by_key(|deposit| (deposit.output_tree, deposit.leaf_index));
        report = wallet.sync(&txs, &deposits, assets, now_unix_ts(), config.tag_window)?;

        if before == (transactions.len(), proofless_deposits.len()) {
            break;
        }
    }

    Ok(report)
}

fn normalized_config(config: SyncWalletConfig) -> SyncWalletConfig {
    SyncWalletConfig {
        tag_window: config.tag_window,
        tag_query_chunk: config.tag_query_chunk.max(1),
        page_limit: config.page_limit.max(1),
        rounds: config.rounds.max(1),
    }
}

fn wallet_query_tags(wallet: &Wallet, window: u64) -> Result<Vec<ViewTag>, ClientError> {
    let mut tags = HashSet::new();
    for entry in &wallet.viewing_key_history {
        tags.insert(entry.key.recipient_bootstrap_view_tag());
        for n in 0..entry.tx_count.saturating_add(window) {
            tags.insert(entry.key.get_sender_view_tag(n)?);
        }
        for n in 0..entry.request_count.saturating_add(window) {
            tags.insert(entry.key.get_recipient_request_view_tag(n)?);
        }
        for (sender, count) in &entry.known_senders {
            for n in 0..count.saturating_add(window) {
                tags.insert(entry.key.get_recipient_shared_view_tag(sender, n)?);
            }
        }
        for (recipient, count) in &entry.known_recipients {
            for n in 0..count.saturating_add(window) {
                tags.insert(entry.key.get_send_shared_view_tag(recipient, n)?);
            }
        }
    }
    Ok(tags.into_iter().collect())
}

fn fetch_shielded_transactions<I: Rpc>(
    indexer: &I,
    tags: &[ViewTag],
    out: &mut HashMap<String, SyncTransaction>,
    config: SyncWalletConfig,
) -> Result<(), ClientError> {
    for chunk in tags.chunks(config.tag_query_chunk) {
        let mut cursor = None;
        loop {
            let response = indexer.get_shielded_transactions_by_tags(
                chunk.to_vec(),
                cursor,
                Some(config.page_limit),
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

fn fetch_proofless_deposits<I, E>(
    indexer: &I,
    event_source: &E,
    tags: &[ViewTag],
    out: &mut HashMap<String, DepositView>,
    config: SyncWalletConfig,
) -> Result<(), ClientError>
where
    I: Rpc,
    E: ProoflessDepositEventSource,
{
    for chunk in tags.chunks(config.tag_query_chunk) {
        let mut cursor = None;
        loop {
            let response = indexer.get_encrypted_utxos_by_tags(
                chunk.to_vec(),
                cursor,
                Some(config.page_limit),
            )?;
            for item in response.matches {
                if item.tx_viewing_pk.is_some() {
                    continue;
                }
                let key = item.tx_signature.to_string();
                if out.contains_key(&key) {
                    continue;
                }
                if let Some(view) = event_source
                    .proofless_deposit_from_signature(item.tx_signature, item.view_tag)?
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

fn convert_sync_transaction(tx: ShieldedTransaction) -> Result<SyncTransaction, ClientError> {
    let tx_viewing_pk = tx
        .tx_viewing_pk
        .ok_or_else(|| ClientError::Rpc("indexed transaction missing tx_viewing_pk".into()))?;
    let salt = tx
        .salt
        .ok_or_else(|| ClientError::Rpc("indexed transaction missing salt".into()))?;
    Ok(SyncTransaction {
        scheme: zolana_transaction::TRANSFER,
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

fn now_unix_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(feature = "solana-rpc")]
impl ProoflessDepositEventSource for crate::solana_rpc::SolanaRpc {
    fn proofless_deposit_from_signature(
        &self,
        signature: Signature,
        view_tag: ViewTag,
    ) -> Result<Option<DepositView>, ClientError> {
        use zolana_interface::{
            event::{indexed_events_from_instruction_groups, proofless_output},
            PROGRAM_ID_PUBKEY,
        };

        let groups = self.fetch_confirmed_instruction_groups(&signature)?.groups;
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
}
