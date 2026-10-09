use std::{
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
use zolana_transaction::{verify_spendable, AssetRegistry, DecryptionResult, ShieldedTransaction};

use super::reservations::{Reservations, TrackedUtxo};
use crate::{api::Inner, error::MakerError, transactions::coordinator::Event};

const PAGE_LIMIT: u32 = 1_000;
const NULLIFIER_CHUNK: usize = 64;

pub struct AccountSync {
    keys: Arc<ShieldedKeypair>,
    indexer: Arc<AsyncZolanaIndexer>,
    reservations: Arc<Reservations>,
    registry: Arc<RwLock<AssetRegistry>>,
    tags: Vec<[u8; 32]>,
    transactions_cursor: Option<Vec<u8>>,
    deposits_cursor: Option<Vec<u8>>,
    decrypted: DecryptionResult,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncOutcome {
    pub inserted: usize,
    pub removed: usize,
}

impl SyncOutcome {
    pub fn changed(&self) -> bool {
        self.inserted > 0 || self.removed > 0
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
            decrypted: DecryptionResult::default(),
        })
    }

    pub fn rescan(&mut self) {
        self.transactions_cursor = None;
        self.deposits_cursor = None;
        self.decrypted = DecryptionResult::default();
    }

    pub async fn run_once(&mut self) -> Result<SyncOutcome, MakerError> {
        let mut fetched = self.transactions().await?;
        fetched.extend(self.deposits().await?);
        fetched.extend(self.spends().await?);
        let registry = self
            .registry
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        self.decrypted
            .extend(self.keys.as_ref(), &fetched, &registry)?;
        let spendable = verify_spendable(self.keys.as_ref(), &self.decrypted)?;
        let mut inserted = 0;
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
            if self.reservations.insert(tracked) {
                inserted += 1;
            }
        }
        let spent = &self.decrypted.spent_nullifiers;
        let removed = self
            .reservations
            .remove_spent_nullifiers(|nullifier| spent.contains(nullifier));
        Ok(SyncOutcome { inserted, removed })
    }

    async fn transactions(&mut self) -> Result<Vec<ShieldedTransaction>, MakerError> {
        let mut fetched = Vec::new();
        loop {
            let response = self
                .indexer
                .get_shielded_transactions_by_tags(
                    self.tags.clone(),
                    self.transactions_cursor.clone(),
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
            if !advance(
                &mut self.transactions_cursor,
                response.next_cursor,
                response.scanned_through,
            ) {
                return Ok(fetched);
            }
        }
    }

    async fn deposits(&mut self) -> Result<Vec<ShieldedTransaction>, MakerError> {
        let mut fetched = Vec::new();
        loop {
            let response = self
                .indexer
                .get_encrypted_utxos_by_tags(
                    self.tags.clone(),
                    self.deposits_cursor.clone(),
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
            if !advance(
                &mut self.deposits_cursor,
                response.next_cursor,
                response.scanned_through,
            ) {
                return Ok(fetched);
            }
        }
    }

    async fn spends(&self) -> Result<Vec<ShieldedTransaction>, MakerError> {
        let unspent: Vec<[u8; 32]> = self.reservations.nullifiers();
        let mut fetched = Vec::new();
        for chunk in unspent.chunks(NULLIFIER_CHUNK) {
            let mut cursor = None;
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
