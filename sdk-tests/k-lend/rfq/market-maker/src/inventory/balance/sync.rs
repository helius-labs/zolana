use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, PoisonError, RwLock},
    time::Duration,
};

use solana_address::Address;
use tokio::{
    sync::{mpsc, Mutex},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use zolana_client::{AsyncRpc, AsyncZolanaIndexer};
use zolana_interface::{pda, state::SplAssetRegistry};
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{
    verify_spendable, AssetRegistry, DecryptionResult, ShieldedKeys, ShieldedTransaction,
};

use super::reservations::{InsertOutcome, Reservations, TrackedUtxo};
use crate::{api::Inner, error::MakerError, transactions::coordinator::Event};

#[cfg(test)]
mod tests;

const PAGE_LIMIT: u32 = 1_000;
const NULLIFIER_CHUNK: usize = 64;

pub struct AccountSync {
    keys: Arc<dyn ShieldedKeys + Send + Sync>,
    indexer: Arc<AsyncZolanaIndexer>,
    reservations: Arc<Reservations>,
    registry: Arc<RwLock<AssetRegistry>>,
    tags: Vec<[u8; 32]>,
    transactions_cursor: Option<Vec<u8>>,
    deposits_cursor: Option<Vec<u8>>,
    spend_cursors: HashMap<[u8; 32], Option<Vec<u8>>>,
    decrypted: DecryptionResult,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncOutcome {
    pub inserted: usize,
    pub indexed: usize,
    pub removed: usize,
}

impl SyncOutcome {
    pub fn changed(&self) -> bool {
        self.inserted > 0 || self.indexed > 0 || self.removed > 0
    }
}

impl AccountSync {
    pub fn new(
        keys: Arc<ShieldedKeypair>,
        indexer: Arc<AsyncZolanaIndexer>,
        reservations: Arc<Reservations>,
        registry: Arc<RwLock<AssetRegistry>>,
    ) -> Result<Self, MakerError> {
        let address = keys.shielded_address()?;
        let tags = vec![
            address.confidential_view_tag()?,
            keys.recipient_bootstrap_view_tag(),
        ];
        Ok(Self {
            keys,
            indexer,
            reservations,
            registry,
            tags,
            transactions_cursor: None,
            deposits_cursor: None,
            spend_cursors: HashMap::new(),
            decrypted: DecryptionResult::default(),
        })
    }

    pub fn rescan(&mut self) {
        self.transactions_cursor = None;
        self.deposits_cursor = None;
        self.spend_cursors.clear();
        self.decrypted = DecryptionResult::default();
    }

    pub async fn run_once(&mut self) -> Result<SyncOutcome, MakerError> {
        let mut transactions_cursor = self.transactions_cursor.clone();
        let mut deposits_cursor = self.deposits_cursor.clone();
        let mut spend_cursors = self.spend_cursors.clone();
        let mut fetched = self.transactions(&mut transactions_cursor).await?;
        fetched.extend(self.deposits(&mut deposits_cursor).await?);
        fetched.extend(self.spends(&mut spend_cursors).await?);
        let registry = self
            .registry
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let mut decrypted = self.decrypted.clone();
        let known: HashSet<_> = decrypted.utxos.iter().map(|utxo| utxo.utxo_hash).collect();
        decrypted.extend(self.keys.as_ref(), &fetched, &registry)?;
        let delta = DecryptionResult {
            utxos: decrypted
                .utxos
                .iter()
                .filter(|utxo| !known.contains(&utxo.utxo_hash))
                .cloned()
                .collect(),
            spent_nullifiers: decrypted.spent_nullifiers.clone(),
            ..DecryptionResult::default()
        };
        let spendable = verify_spendable(self.keys.as_ref(), &delta)?;
        let verified: HashSet<_> = spendable.utxos().map(|utxo| utxo.utxo_hash).collect();
        let removed = self
            .reservations
            .remove_spent_nullifiers(decrypted.spent_nullifiers.iter().copied());
        let mut inserted = 0;
        let mut indexed = 0;
        for utxo in spendable
            .balances
            .assets
            .into_iter()
            .flat_map(|balance| balance.utxos)
        {
            if utxo.utxo.amount == 0 {
                continue;
            }
            let tracked = TrackedUtxo {
                leaf_index: Some(utxo.leaf_index),
                wallet: utxo,
            };
            match self.reservations.insert(tracked) {
                InsertOutcome::Added => inserted += 1,
                InsertOutcome::Indexed => indexed += 1,
                InsertOutcome::Unchanged | InsertOutcome::AlreadySpent => {}
            }
        }
        let merge_inputs: HashSet<_> = decrypted
            .pending_merges
            .iter()
            .flat_map(|merge| merge.nullifiers.iter().copied())
            .collect();
        decrypted.utxos.retain(|utxo| {
            let needed = merge_inputs.contains(&utxo.nullifier);
            (known.contains(&utxo.utxo_hash) || verified.contains(&utxo.utxo_hash) || needed)
                && (!self.reservations.is_spent(&utxo.nullifier) || needed)
        });
        // Reservation tombstones preserve replay protection without re-scanning spends.
        decrypted.spent_nullifiers.clear();
        self.decrypted = decrypted;
        self.transactions_cursor = transactions_cursor;
        self.deposits_cursor = deposits_cursor;
        let live: HashSet<_> = self.reservations.nullifiers().into_iter().collect();
        spend_cursors.retain(|nullifier, _| live.contains(nullifier));
        self.spend_cursors = spend_cursors;
        Ok(SyncOutcome {
            inserted,
            indexed,
            removed,
        })
    }

    async fn transactions(
        &self,
        cursor: &mut Option<Vec<u8>>,
    ) -> Result<Vec<ShieldedTransaction>, MakerError> {
        let mut fetched = Vec::new();
        loop {
            let response = self
                .indexer
                .get_shielded_transactions_by_tags(
                    self.tags.clone(),
                    cursor.clone(),
                    Some(PAGE_LIMIT),
                    None,
                )
                .await
                .map_err(MakerError::Sync)?;
            fetched.extend(
                response
                    .transactions
                    .into_iter()
                    .filter(|tx| !tx.proofless && tx.tx_viewing_pk.is_some() && tx.salt.is_some()),
            );
            if !advance(cursor, response.next_cursor, response.scanned_through) {
                return Ok(fetched);
            }
        }
    }

    async fn deposits(
        &self,
        cursor: &mut Option<Vec<u8>>,
    ) -> Result<Vec<ShieldedTransaction>, MakerError> {
        let mut fetched = Vec::new();
        loop {
            let response = self
                .indexer
                .get_encrypted_utxos_by_tags(
                    self.tags.clone(),
                    cursor.clone(),
                    Some(PAGE_LIMIT),
                    None,
                )
                .await
                .map_err(MakerError::Sync)?;
            fetched.extend(
                response
                    .matches
                    .into_iter()
                    .filter_map(|item| item.into_proofless_transaction()),
            );
            if !advance(cursor, response.next_cursor, response.scanned_through) {
                return Ok(fetched);
            }
        }
    }

    async fn spends(
        &self,
        cursors: &mut HashMap<[u8; 32], Option<Vec<u8>>>,
    ) -> Result<Vec<ShieldedTransaction>, MakerError> {
        let unspent: Vec<[u8; 32]> = self.reservations.nullifiers();
        let mut groups: BTreeMap<Option<Vec<u8>>, Vec<[u8; 32]>> = BTreeMap::new();
        for nullifier in unspent {
            groups
                .entry(cursors.get(&nullifier).cloned().flatten())
                .or_default()
                .push(nullifier);
        }
        let mut fetched = Vec::new();
        for (position, nullifiers) in groups {
            for chunk in nullifiers.chunks(NULLIFIER_CHUNK) {
                let mut cursor = position.clone();
                loop {
                    let response = self
                        .indexer
                        .get_shielded_transactions_by_nullifiers(
                            chunk.to_vec(),
                            cursor.clone(),
                            Some(PAGE_LIMIT),
                            None,
                        )
                        .await
                        .map_err(MakerError::Sync)?;
                    fetched.extend(response.transactions.into_iter().filter(|tx| !tx.proofless));
                    if !advance(&mut cursor, response.next_cursor, response.scanned_through) {
                        break;
                    }
                }
                for nullifier in chunk {
                    cursors.insert(*nullifier, cursor.clone());
                }
            }
        }
        Ok(fetched)
    }
}

fn advance(
    position: &mut Option<Vec<u8>>,
    next_cursor: Option<Vec<u8>>,
    scanned_through: Option<Vec<u8>>,
) -> bool {
    let more = next_cursor.is_some();
    if let Some(next) = scanned_through.or(next_cursor) {
        *position = Some(next);
    }
    more
}

pub fn spawn_sync(
    account: Arc<Mutex<AccountSync>>,
    interval: Duration,
    events: mpsc::UnboundedSender<Event>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tick.tick() => match account.lock().await.run_once().await {
                    Ok(outcome) if outcome.changed() => {
                        let _ = events.send(Event::Synced);
                    }
                    Ok(_) => {}
                    Err(error) => tracing::warn!(%error, "sync failed"),
                },
            }
        }
    })
}

impl Inner {
    pub async fn sync(&self) -> Result<(), MakerError> {
        self.account.lock().await.run_once().await?;
        self.runtime
            .events
            .send(Event::Synced)
            .map_err(|_| MakerError::CoordinatorStopped)
    }
}

pub async fn registered_asset(rpc: &dyn AsyncRpc, mint: Address) -> Result<u64, MakerError> {
    let account = rpc
        .get_account(pda::spl_asset_registry(&mint))
        .await
        .map_err(MakerError::Rpc)?
        .ok_or(MakerError::AssetNotRegistered { mint })?;
    SplAssetRegistry::from_account_bytes(&account.data)
        .map(|registry| registry.asset_id)
        .map_err(|error| MakerError::AssetRegistry {
            mint,
            reason: format!("{error:?}"),
        })
}

pub async fn asset_registry(
    rpc: &dyn AsyncRpc,
    mints: impl IntoIterator<Item = Address>,
) -> Result<AssetRegistry, MakerError> {
    let mut registry = AssetRegistry::default();
    for mint in mints {
        registry.insert(registered_asset(rpc, mint).await?, mint)?;
    }
    Ok(registry)
}
