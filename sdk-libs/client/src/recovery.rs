//! A wallet's anonymous ring notes read without tags.
//!
//! The exact tags of [`UtxoScan`](crate::UtxoScan) are the fast path. A capped
//! tag, a sender's wrong tag or a wallet without tag state falls back to every
//! confirmed transaction of the ring from the checkpoint through the stated
//! head, one key agreement per transaction and held viewing key, every scheme-9
//! slot accepted on commitment equality alone.

use std::num::NonZeroUsize;

use solana_address::Address;
use zolana_transaction::{
    verify_owned, AnonymousNote, AssetRegistry, DecryptionResult, OwnedUtxos, PairHintError,
    ShieldedKeys, SpendableDecryptionResult,
};

use crate::{
    error::ClientError,
    rpc::{IndexerRpcConfig, RingHistoryOptions, Rpc, ShieldedTransaction},
    scan::{next_page, PAGE_LIMIT},
};

/// Pages of [`PAGE_LIMIT`] transactions one recovery reads before it fails.
pub const DEFAULT_RECOVERY_PAGE_LIMIT: NonZeroUsize = NonZeroUsize::new(1_024).unwrap();

/// One full read of a ring's history for the wallet's notes, configured and then
/// [`fetch`](Self::fetch) once.
pub struct RingRecovery<'a, K: ?Sized> {
    keys: &'a K,
    assets: &'a AssetRegistry,
    ring_program_id: Address,
    head: u64,
    checkpoint: Option<Vec<u8>>,
    page_limit: NonZeroUsize,
    indexer_config: Option<IndexerRpcConfig>,
}

/// What one recovery read, complete relative to the indexer, paging detects a
/// truncated page and never a transaction the indexer omitted.
#[derive(Clone, Debug)]
pub struct RingRecoveryResult {
    /// Every note the wallet owns among the ring's transactions, spent or not.
    pub owned: OwnedUtxos,
    pub spendable: SpendableDecryptionResult,
    pub transactions: Vec<ShieldedTransaction>,
    pub report: RingRecoveryReport,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingRecoveryReport {
    pub ring_program_id: Address,
    /// Transactions past `head` wait for the next recovery.
    pub head: u64,
    /// The indexer frontier, the checkpoint of the next recovery.
    pub checkpoint: Vec<u8>,
    pub notes: Vec<AnonymousNote>,
    pub bad_pair_hints: Vec<PairHintError>,
}

pub(crate) struct Recovered {
    pub(crate) transactions: Vec<ShieldedTransaction>,
    pub(crate) report: RingRecoveryReport,
}

struct RingHistory {
    transactions: Vec<ShieldedTransaction>,
    frontier: Vec<u8>,
}

impl<'a, K: ShieldedKeys + ?Sized> RingRecovery<'a, K> {
    /// Reads from ring creation through `head`, a confirmed slot the caller states.
    pub fn new(
        keys: &'a K,
        assets: &'a AssetRegistry,
        ring_program_id: Address,
        head: u64,
    ) -> Self {
        Self {
            keys,
            assets,
            ring_program_id,
            head,
            checkpoint: None,
            page_limit: DEFAULT_RECOVERY_PAGE_LIMIT,
            indexer_config: None,
        }
    }

    /// Resumes at the frontier an earlier [`RingRecoveryReport`] returned.
    #[must_use]
    pub fn with_checkpoint(mut self, checkpoint: Vec<u8>) -> Self {
        self.checkpoint = Some(checkpoint);
        self
    }

    #[must_use]
    pub fn with_page_limit(mut self, pages: NonZeroUsize) -> Self {
        self.page_limit = pages;
        self
    }

    /// As on [`UtxoScan::with_indexer_config`](crate::UtxoScan::with_indexer_config).
    #[must_use]
    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.indexer_config = Some(config);
        self
    }

    pub fn fetch<I: Rpc + ?Sized>(&self, indexer: &I) -> Result<RingRecoveryResult, ClientError> {
        let mut decrypted = DecryptionResult::default();
        let recovered = self.open_into(indexer, &mut decrypted)?;
        let owned = verify_owned(self.keys, &decrypted)?;
        Ok(RingRecoveryResult {
            spendable: owned.spendable(),
            owned,
            transactions: recovered.transactions,
            report: recovered.report,
        })
    }

    /// Opens the ring's slots into a result another scan already filled.
    pub(crate) fn open_into<I: Rpc + ?Sized>(
        &self,
        indexer: &I,
        decrypted: &mut DecryptionResult,
    ) -> Result<Recovered, ClientError> {
        let history = self.history(indexer)?;
        let found = decrypted.extend_ring_anonymous_untagged(
            self.keys,
            &history.transactions,
            self.assets,
        )?;
        Ok(Recovered {
            transactions: history.transactions,
            report: RingRecoveryReport {
                ring_program_id: self.ring_program_id,
                head: self.head,
                checkpoint: history.frontier,
                notes: found.notes,
                bad_pair_hints: found.bad_pair_hints,
            },
        })
    }

    /// Every ring transaction through `head`, the last page must state the
    /// indexer's frontier and a history cut by the page limit is an error.
    fn history<I: Rpc + ?Sized>(&self, indexer: &I) -> Result<RingHistory, ClientError> {
        let mut transactions = Vec::new();
        let mut cursor = self.checkpoint.clone();
        let mut pages = 0;
        loop {
            let page = indexer.get_shielded_transactions_by_ring(
                RingHistoryOptions {
                    ring_program_id: self.ring_program_id,
                    cursor: cursor.clone(),
                    limit: Some(PAGE_LIMIT),
                },
                self.indexer_config,
            )?;
            pages += 1;
            transactions.extend(
                page.transactions
                    .into_iter()
                    .filter(|tx| tx.ring_program_id == Some(self.ring_program_id))
                    .filter(|tx| tx.slot <= self.head),
            );
            let frontier = page.scanned_through.clone();
            match next_page(&cursor, page.next_cursor, &frontier)? {
                Some(_) if pages == self.page_limit.get() => {
                    return Err(ClientError::RingHistoryPageLimit {
                        ring_program_id: self.ring_program_id,
                        pages,
                    });
                }
                Some(next) => cursor = Some(next),
                None => {
                    let frontier = frontier.ok_or(ClientError::RingHistoryIncomplete {
                        ring_program_id: self.ring_program_id,
                    })?;
                    return Ok(RingHistory {
                        transactions,
                        frontier,
                    });
                }
            }
        }
    }
}
