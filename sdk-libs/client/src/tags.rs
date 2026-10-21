//! Exact-tag reads of the indexer, an output nobody can decrypt still occupies its tag.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    future::Future,
};

use solana_signature::Signature;
use zolana_keypair::{viewing_key::ViewTag, KeypairError};

use crate::{
    error::ClientError,
    rpc::{
        AsyncRpc, Context, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse,
        GetShieldedTransactionsByNullifiersResponse, GetShieldedTransactionsByTagsResponse,
        IndexerRpcConfig, ShieldedTransaction,
    },
    scan::{next_page, PAGE_LIMIT},
};

/// Indices probed per indexer query.
pub const DEFAULT_TAG_WINDOW: u64 = 64;

/// The indexer's cap on the tags or nullifiers one request names.
pub const TAGS_PER_REQUEST: usize = zolana_indexer_api::PAGE_LIMIT as usize;

#[derive(Clone, Debug)]
pub struct TagWindow {
    by_tag: HashMap<ViewTag, u64>,
}

impl TagWindow {
    /// `tags` in index order from `start`, a short list ends the window early.
    pub fn new(start: u64, tags: impl IntoIterator<Item = ViewTag>) -> Self {
        Self {
            by_tag: tags.into_iter().zip(indices(start)).collect(),
        }
    }

    pub fn derive(
        start: u64,
        tag_at: impl Fn(u64) -> Result<ViewTag, KeypairError>,
    ) -> Result<Self, KeypairError> {
        let tags = indices(start)
            .map(tag_at)
            .collect::<Result<Vec<_>, KeypairError>>()?;
        Ok(Self::new(start, tags))
    }

    pub fn tags(&self) -> Vec<ViewTag> {
        self.by_tag.keys().copied().collect()
    }

    pub fn index_of(&self, tag: &ViewTag) -> Option<u64> {
        self.by_tag.get(tag).copied()
    }

    pub fn occupied<'a>(
        &self,
        transactions: impl IntoIterator<Item = &'a ShieldedTransaction>,
    ) -> BTreeSet<u64> {
        occupied(&self.by_tag, transactions)
    }

    pub fn first_free(start: u64, occupied: &BTreeSet<u64>) -> Option<u64> {
        indices(start).find(|index| !occupied.contains(index))
    }
}

#[derive(Clone, Debug, Default)]
pub struct TagReservations {
    start: u64,
    /// The occupied indices of the window at `start`, `None` before its read.
    occupied: Option<BTreeSet<u64>>,
    reserved: BTreeSet<u64>,
}

impl From<u64> for TagReservations {
    /// Starts the stream at `start`, the lowest index the caller still considers free.
    fn from(start: u64) -> Self {
        Self {
            start,
            ..Self::default()
        }
    }
}

impl TagReservations {
    pub fn reserved(&self) -> &BTreeSet<u64> {
        &self.reserved
    }
}

pub struct TagStream<'a, I: ?Sized> {
    indexer: &'a I,
    config: Option<IndexerRpcConfig>,
}

impl<'a, I: AsyncRpc + ?Sized> TagStream<'a, I> {
    pub fn new(indexer: &'a I) -> Self {
        Self {
            indexer,
            config: None,
        }
    }

    #[must_use]
    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// The lowest index at or after `start` with no output under its tag.
    pub async fn first_free_index(
        &self,
        start: u64,
        tag_at: impl Fn(u64) -> Result<ViewTag, KeypairError>,
    ) -> Result<u64, ClientError> {
        self.reserve_index(&mut TagReservations::from(start), tag_at)
            .await
    }

    /// The lowest index free in history and not yet reserved, recorded in `reservations`.
    pub async fn reserve_index(
        &self,
        reservations: &mut TagReservations,
        tag_at: impl Fn(u64) -> Result<ViewTag, KeypairError>,
    ) -> Result<u64, ClientError> {
        loop {
            let occupied = match &reservations.occupied {
                Some(occupied) => occupied,
                None => {
                    let occupied = self.occupied_indices(reservations.start, &tag_at).await?;
                    reservations.occupied.insert(occupied)
                }
            };
            let free = indices(reservations.start)
                .find(|index| !occupied.contains(index) && !reservations.reserved.contains(index));
            match free {
                Some(index) => {
                    reservations.reserved.insert(index);
                    return Ok(index);
                }
                None => {
                    reservations.start = reservations
                        .start
                        .checked_add(DEFAULT_TAG_WINDOW)
                        .ok_or(ClientError::TagStreamExhausted)?;
                    reservations.occupied = None;
                }
            }
        }
    }

    /// The indices of the window at `start` with at least one output under their tag.
    pub async fn occupied_indices(
        &self,
        start: u64,
        tag_at: impl Fn(u64) -> Result<ViewTag, KeypairError>,
    ) -> Result<BTreeSet<u64>, ClientError> {
        let window = TagWindow::derive(start, tag_at)?;
        let transactions = IndexerReads::configured(self.indexer, self.config)
            .transactions(&window.tags())
            .await?;
        Ok(window.occupied(&transactions))
    }
}

/// Exact-tag and spend reads, keeping the lowest persisted slot any answer reports.
#[must_use]
pub struct IndexerReads<'a, I: ?Sized> {
    indexer: &'a I,
    config: Option<IndexerRpcConfig>,
    persisted: Option<u64>,
}

impl<'a, I: AsyncRpc + ?Sized> IndexerReads<'a, I> {
    pub fn new(indexer: &'a I) -> Self {
        Self::configured(indexer, None)
    }

    pub fn with_indexer_config(self, config: IndexerRpcConfig) -> Self {
        Self {
            config: Some(config),
            ..self
        }
    }

    pub(crate) fn configured(indexer: &'a I, config: Option<IndexerRpcConfig>) -> Self {
        Self {
            indexer,
            config,
            persisted: None,
        }
    }

    /// No epoch past the returned slot's is complete, `None` before the first answer.
    pub fn persisted_slot(&self) -> Option<u64> {
        self.persisted
    }

    /// Every transaction published under one of `tags`, each once.
    pub async fn transactions(
        &mut self,
        tags: &[ViewTag],
    ) -> Result<Vec<ShieldedTransaction>, ClientError> {
        let (indexer, config) = (self.indexer, self.config);
        let transactions = self
            .paged(tags, |tags, cursor| async move {
                indexer
                    .get_shielded_transactions_by_tags(tags, cursor, Some(PAGE_LIMIT), config)
                    .await
                    .map(Page::from)
            })
            .await?;
        let mut seen: HashSet<(Signature, Option<u16>)> = HashSet::new();
        Ok(transactions
            .into_iter()
            .filter(|tx| seen.insert((tx.tx_signature, tx.event_index)))
            .collect())
    }

    /// The deposits published under one of `tags`, one transaction per deposited output.
    pub async fn deposits(
        &mut self,
        tags: &[ViewTag],
    ) -> Result<Vec<ShieldedTransaction>, ClientError> {
        let (indexer, config) = (self.indexer, self.config);
        let matches = self
            .paged(tags, |tags, cursor| async move {
                indexer
                    .get_encrypted_utxos_by_tags(tags, cursor, Some(PAGE_LIMIT), config)
                    .await
                    .map(Page::from)
            })
            .await?;
        Ok(matches
            .into_iter()
            .filter_map(EncryptedUtxoMatch::into_proofless_transaction)
            .collect())
    }

    pub async fn spends(
        &mut self,
        nullifiers: &[[u8; 32]],
    ) -> Result<Vec<ShieldedTransaction>, ClientError> {
        let (indexer, config) = (self.indexer, self.config);
        self.paged(nullifiers, |nullifiers, cursor| async move {
            indexer
                .get_shielded_transactions_by_nullifiers(
                    nullifiers,
                    cursor,
                    Some(PAGE_LIMIT),
                    config,
                )
                .await
                .map(Page::from)
        })
        .await
    }

    async fn paged<T, F, Fut>(
        &mut self,
        queried: &[[u8; 32]],
        fetch: F,
    ) -> Result<Vec<T>, ClientError>
    where
        F: Fn(Vec<[u8; 32]>, Option<Vec<u8>>) -> Fut,
        Fut: Future<Output = Result<Page<T>, ClientError>>,
    {
        let mut items = Vec::new();
        for chunk in queried.chunks(TAGS_PER_REQUEST) {
            let mut cursor = None;
            loop {
                let page = fetch(chunk.to_vec(), cursor.clone()).await?;
                self.observe(&page.context);
                items.extend(page.items);
                match next_page(&cursor, page.next_cursor, &page.scanned_through)? {
                    Some(next) => cursor = Some(next),
                    None => break,
                }
            }
        }
        Ok(items)
    }

    fn observe(&mut self, context: &Context) {
        self.persisted = Some(
            self.persisted
                .map_or(context.slot, |slot| slot.min(context.slot)),
        );
    }
}

struct Page<T> {
    context: Context,
    items: Vec<T>,
    next_cursor: Option<Vec<u8>>,
    scanned_through: Option<Vec<u8>>,
}

macro_rules! pages {
    ($($response:ty => $item:ty, $items:ident;)*) => {$(
        impl From<$response> for Page<$item> {
            fn from(page: $response) -> Self {
                Self {
                    context: page.context,
                    items: page.$items,
                    next_cursor: page.next_cursor,
                    scanned_through: page.scanned_through,
                }
            }
        }
    )*};
}

pages! {
    GetShieldedTransactionsByTagsResponse => ShieldedTransaction, transactions;
    GetShieldedTransactionsByNullifiersResponse => ShieldedTransaction, transactions;
    GetEncryptedUtxosByTagsResponse => EncryptedUtxoMatch, matches;
}

/// The positions of `tags` some output of `transactions` publishes under.
pub(crate) fn occupied<'a, P: Copy + Ord>(
    tags: &HashMap<ViewTag, P>,
    transactions: impl IntoIterator<Item = &'a ShieldedTransaction>,
) -> BTreeSet<P> {
    transactions
        .into_iter()
        .flat_map(|tx| &tx.output_slots)
        .filter_map(|slot| tags.get(&slot.view_tag).copied())
        .collect()
}

pub(crate) fn indices(start: u64) -> impl Iterator<Item = u64> {
    start..=start.saturating_add(DEFAULT_TAG_WINDOW - 1)
}
