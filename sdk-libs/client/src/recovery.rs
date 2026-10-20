//! Anonymous ring notes read from the whole ring history without tags.

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

pub struct RingRecovery<'a, K: ?Sized> {
    keys: &'a K,
    assets: &'a AssetRegistry,
    ring_program_id: Address,
    head: u64,
    checkpoint: Option<Vec<u8>>,
    page_limit: NonZeroUsize,
    indexer_config: Option<IndexerRpcConfig>,
}

/// Complete relative to the indexer, paging never detects an omitted transaction.
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
    /// The cursor the next recovery resumes at, `None` restarts at ring creation.
    pub checkpoint: Option<Vec<u8>>,
    pub notes: Vec<AnonymousNote>,
    pub bad_pair_hints: Vec<PairHintError>,
}

pub(crate) struct Recovered {
    pub(crate) transactions: Vec<ShieldedTransaction>,
    pub(crate) report: RingRecoveryReport,
}

struct RingHistory {
    transactions: Vec<ShieldedTransaction>,
    checkpoint: Option<Vec<u8>>,
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

    /// Resumes at the checkpoint an earlier [`RingRecoveryReport`] returned, the
    /// page it names is read again.
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
        let recovered = self.open_into(indexer, &mut decrypted, Ok)?;
        let owned = verify_owned(self.keys, &decrypted)?;
        Ok(RingRecoveryResult {
            spendable: owned.spendable(),
            owned,
            transactions: recovered.transactions,
            report: recovered.report,
        })
    }

    /// Opens the ring's slots into a result another scan already filled,
    /// `unseen` keeps the transactions it has not decoded yet.
    pub(crate) fn open_into<I, F>(
        &self,
        indexer: &I,
        decrypted: &mut DecryptionResult,
        unseen: F,
    ) -> Result<Recovered, ClientError>
    where
        I: Rpc + ?Sized,
        F: FnOnce(Vec<ShieldedTransaction>) -> Result<Vec<ShieldedTransaction>, ClientError>,
    {
        let history = self.history(indexer)?;
        let found = decrypted.extend_ring_anonymous_untagged(
            self.keys,
            &history.transactions,
            self.assets,
        )?;
        if let Some(malformed) = found.malformed_slots.first() {
            return Err(ClientError::RingHistoryMalformed {
                tx_signature: malformed.tx_signature,
                slot_index: malformed.slot_index,
                defect: malformed.defect,
            });
        }
        // A merge of a recovered note publishes its output on the ordinary path alone.
        let transactions = unseen(history.transactions)?;
        decrypted.extend(self.keys, &transactions, self.assets)?;
        Ok(Recovered {
            transactions,
            report: RingRecoveryReport {
                ring_program_id: self.ring_program_id,
                head: self.head,
                checkpoint: history.checkpoint,
                notes: found.notes,
                bad_pair_hints: found.bad_pair_hints,
            },
        })
    }

    /// Stops at the first page past `head` and checkpoints that page, fails
    /// without a stated frontier, on a frontier short of `head` or past the
    /// page limit.
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
            if let Some(foreign) = page
                .transactions
                .iter()
                .find(|tx| tx.ring_program_id != Some(self.ring_program_id))
            {
                return Err(ClientError::RingHistoryForeignRow {
                    tx_signature: foreign.tx_signature,
                });
            }
            let indexed = page.context.slot;
            let past_head = page.transactions.iter().position(|tx| tx.slot > self.head);
            let through_head = &page.transactions[..past_head.unwrap_or(page.transactions.len())];
            transactions.extend_from_slice(through_head);
            if past_head.is_some() {
                return Ok(RingHistory {
                    transactions,
                    checkpoint: cursor,
                });
            }
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
                    if indexed < self.head {
                        return Err(ClientError::RingHistoryBehindHead {
                            ring_program_id: self.ring_program_id,
                            head: self.head,
                            indexed,
                        });
                    }
                    return Ok(RingHistory {
                        transactions,
                        checkpoint: Some(frontier),
                    });
                }
            }
        }
    }
}
