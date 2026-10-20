//! Occupancy of a tag stream, an output nobody can decrypt still occupies its index.

use std::collections::{BTreeSet, HashMap};

use zolana_keypair::{viewing_key::ViewTag, KeypairError};

use crate::{
    error::ClientError,
    rpc::{AsyncRpc, IndexerRpcConfig, ShieldedTransaction},
    scan::{next_page, PAGE_LIMIT},
};

/// Indices probed per indexer query.
pub const DEFAULT_TAG_WINDOW: u64 = 64;

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
        transactions
            .into_iter()
            .flat_map(|tx| &tx.output_slots)
            .filter_map(|slot| self.index_of(&slot.view_tag))
            .collect()
    }

    pub fn first_free(start: u64, occupied: &BTreeSet<u64>) -> Option<u64> {
        indices(start).find(|index| !occupied.contains(index))
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
        let mut start = start;
        loop {
            let occupied = self.occupied_indices(start, &tag_at).await?;
            if let Some(free) = TagWindow::first_free(start, &occupied) {
                return Ok(free);
            }
            start = start
                .checked_add(DEFAULT_TAG_WINDOW)
                .ok_or(ClientError::TagStreamExhausted)?;
        }
    }

    /// The indices of the window at `start` with at least one output under their tag.
    pub async fn occupied_indices(
        &self,
        start: u64,
        tag_at: impl Fn(u64) -> Result<ViewTag, KeypairError>,
    ) -> Result<BTreeSet<u64>, ClientError> {
        let window = TagWindow::derive(start, tag_at)?;
        let queried = window.tags();
        let mut occupied = BTreeSet::new();
        let mut cursor = None;
        loop {
            let page = self
                .indexer
                .get_shielded_transactions_by_tags(
                    queried.clone(),
                    cursor.clone(),
                    Some(PAGE_LIMIT),
                    self.config,
                )
                .await?;
            occupied.extend(window.occupied(&page.transactions));
            match next_page(&cursor, page.next_cursor, &page.scanned_through)? {
                Some(next) => cursor = Some(next),
                None => return Ok(occupied),
            }
        }
    }
}

pub(crate) fn indices(start: u64) -> impl Iterator<Item = u64> {
    start..=start.saturating_add(DEFAULT_TAG_WINDOW - 1)
}
