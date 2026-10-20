//! Occupancy of a tag stream, an output nobody can decrypt still occupies its index.

use std::collections::{BTreeSet, HashMap};

use zolana_keypair::{viewing_key::ViewTag, KeypairError};

use crate::{
    error::ClientError,
    rpc::{AsyncRpc, IndexerRpcConfig},
    scan::{next_page, PAGE_LIMIT},
};

/// Indices probed per indexer query.
pub const DEFAULT_TAG_WINDOW: u64 = 64;

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
            if let Some(free) = window(start).find(|index| !occupied.contains(index)) {
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
        let tags = window(start)
            .map(|index| Ok((tag_at(index)?, index)))
            .collect::<Result<HashMap<ViewTag, u64>, KeypairError>>()?;
        let queried: Vec<ViewTag> = tags.keys().copied().collect();
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
            occupied.extend(
                page.transactions
                    .iter()
                    .flat_map(|tx| &tx.output_slots)
                    .filter_map(|slot| tags.get(&slot.view_tag)),
            );
            match next_page(&cursor, page.next_cursor, &page.scanned_through)? {
                Some(next) => cursor = Some(next),
                None => return Ok(occupied),
            }
        }
    }
}

fn window(start: u64) -> impl Iterator<Item = u64> {
    start..=start.saturating_add(DEFAULT_TAG_WINDOW - 1)
}
