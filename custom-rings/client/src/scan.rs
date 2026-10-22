//! Finding the transactions an auditor can open.
//!
//! The auditor scans for its own view tag, which is the auditor key's
//! x-coordinate ([`auditor_view_tag`]). Photon's
//! `get_shielded_transactions_by_tags` matches the requested tags against both
//! output view tags and MESSAGE view tags (an OR of two EXISTS subqueries in
//! `services/photon/src/api/method/rings/get_shielded_transactions_by_tags.rs`)
//! and hydrates the matching transactions' messages back, which is what makes it
//! usable here. `get_encrypted_utxos_by_tags` matches outputs only and would
//! never see an auditor message.
//!
//! The indexer knows nothing about rings. Each matched transaction is
//! attributed to the ring through its confirmed call stack
//! ([`TransactionOrigin`]).

use custom_ring_interface::RingMode;
use std::{
    collections::HashMap,
    num::{NonZeroU32, NonZeroUsize},
};
use zolana_keypair::{X25519Keypair, X25519Pubkey};

use solana_signature::Signature;
use zolana_client::{rpc::Cursor, IndexerRpcConfig, Rpc};
use zolana_transaction::{AssetRegistry, ShieldedTransaction};

use crate::{
    decrypt::TransactionAudit, encryption::auditor_view_tag, error::AuditError,
    origin::TransactionOrigin, types::AuditedTransaction,
};

pub struct RingEnvironment<'a, I, O> {
    pub indexer: &'a I,
    pub origin: &'a O,
}

impl<I, O> Clone for RingEnvironment<'_, I, O> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<I, O> Copy for RingEnvironment<'_, I, O> {}

pub struct RingScanPage {
    pub transactions: Vec<ShieldedTransaction>,
    pub next: Option<Cursor>,
}

pub struct AuditedPage {
    pub transactions: Vec<AuditedTransaction>,
    pub next: Option<Cursor>,
}

#[must_use = "run or discard the scan explicitly"]
/// Every indexed transaction that carries a message tagged for `auditor_key`.
///
/// The tag match is re-applied to the returned messages because the indexer
/// matches output tags and message tags.
pub struct RingScan<'a> {
    ring_program_id: solana_address::Address,
    auditor_key: &'a X25519Pubkey,
    after: Option<Cursor>,
    page_size: NonZeroU32,
    max_pages: NonZeroUsize,
    indexer_config: Option<IndexerRpcConfig>,
}

#[must_use = "run or discard the audit explicitly"]
/// Scans and audits the bounded page range in one operation.
pub struct RingAudit<'a> {
    ring_program_id: solana_address::Address,
    auditor: &'a X25519Keypair,
    mode: RingMode,
    after: Option<Cursor>,
    page_size: NonZeroU32,
    max_pages: NonZeroUsize,
    indexer_config: Option<IndexerRpcConfig>,
}

const DEFAULT_MAX_PAGES: NonZeroUsize = match NonZeroUsize::new(32) {
    Some(value) => value,
    None => NonZeroUsize::MIN,
};
const DEFAULT_PAGE_SIZE: NonZeroU32 = match NonZeroU32::new(100) {
    Some(limit) => limit,
    None => NonZeroU32::MIN,
};

impl<'a> RingScan<'a> {
    pub fn new(ring_program_id: solana_address::Address, auditor_key: &'a X25519Pubkey) -> Self {
        Self {
            ring_program_id,
            auditor_key,
            after: None,
            page_size: DEFAULT_PAGE_SIZE,
            max_pages: DEFAULT_MAX_PAGES,
            indexer_config: None,
        }
    }

    #[must_use = "use the updated scan"]
    pub fn with_after(mut self, after: Cursor) -> Self {
        self.after = Some(after);
        self
    }

    #[must_use = "use the updated scan"]
    pub fn with_page_size(mut self, page_size: NonZeroU32) -> Self {
        self.page_size = page_size;
        self
    }

    #[must_use = "use the updated scan"]
    pub fn with_max_pages(mut self, max_pages: NonZeroUsize) -> Self {
        self.max_pages = max_pages;
        self
    }

    /// Every page waits until the indexer has persisted
    /// `config.require_slot`.
    #[must_use = "use the updated scan"]
    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.indexer_config = Some(config);
        self
    }

    #[must_use = "use the updated scan"]
    pub(crate) fn indexer_config(mut self, config: Option<IndexerRpcConfig>) -> Self {
        self.indexer_config = config;
        self
    }

    pub fn run<I: Rpc, O: TransactionOrigin>(
        self,
        env: RingEnvironment<'_, I, O>,
    ) -> Result<RingScanPage, AuditError> {
        let view_tag = auditor_view_tag(self.auditor_key);
        let mut transactions = Vec::new();
        let mut after = self.after;
        let mut origins: HashMap<(Signature, u16), bool> = HashMap::new();
        for _ in 0..self.max_pages.get() {
            let page = env.indexer.get_shielded_transactions_by_tags(
                vec![view_tag],
                after,
                Some(self.page_size.get()),
                self.indexer_config,
            )?;
            let next = page
                .continuation(after)
                .map_err(|_| AuditError::CursorNotAdvanced)?;
            for tx in page.items.into_iter().flat_map(|item| item.events) {
                if tx.ring_program_id != Some(self.ring_program_id) {
                    continue;
                }
                if !tx
                    .messages
                    .iter()
                    .any(|message| message.view_tag == view_tag)
                {
                    continue;
                }
                let event_index = tx.event_index.ok_or(AuditError::MissingEventIndex)?;
                let origin_key = (tx.tx_signature, event_index);
                let ring_invoked = match origins.get(&origin_key) {
                    Some(known) => *known,
                    None => {
                        let invoked = env.origin.ring_invoked(
                            tx.tx_signature,
                            event_index,
                            self.ring_program_id,
                        )?;
                        origins.insert(origin_key, invoked);
                        invoked
                    }
                };
                if ring_invoked {
                    transactions.push(tx);
                }
            }
            let Some(next) = next else {
                return Ok(RingScanPage {
                    transactions,
                    next: None,
                });
            };
            after = Some(next);
        }
        Ok(RingScanPage {
            transactions,
            next: after,
        })
    }
}

impl<'a> RingAudit<'a> {
    pub fn new(ring_program_id: solana_address::Address, auditor: &'a X25519Keypair) -> Self {
        Self {
            ring_program_id,
            auditor,
            mode: RingMode::Off,
            after: None,
            page_size: DEFAULT_PAGE_SIZE,
            max_pages: DEFAULT_MAX_PAGES,
            indexer_config: None,
        }
    }

    /// Selects the ring's proved disclosure layout before auditing its slots.
    #[must_use = "use the updated audit"]
    pub fn with_mode(mut self, mode: RingMode) -> Self {
        self.mode = mode;
        self
    }

    #[must_use = "use the updated audit"]
    pub fn with_after(mut self, after: Cursor) -> Self {
        self.after = Some(after);
        self
    }

    #[must_use = "use the updated audit"]
    pub fn with_page_size(mut self, page_size: NonZeroU32) -> Self {
        self.page_size = page_size;
        self
    }

    #[must_use = "use the updated audit"]
    pub fn with_max_pages(mut self, max_pages: NonZeroUsize) -> Self {
        self.max_pages = max_pages;
        self
    }

    /// Every page waits until the indexer has persisted
    /// `config.require_slot`.
    #[must_use = "use the updated audit"]
    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.indexer_config = Some(config);
        self
    }

    pub fn run<I: Rpc, O: TransactionOrigin>(
        self,
        env: RingEnvironment<'_, I, O>,
        assets: &AssetRegistry,
    ) -> Result<AuditedPage, AuditError> {
        let auditor_key = self.auditor.pubkey();
        let mut scan = RingScan::new(self.ring_program_id, &auditor_key)
            .with_page_size(self.page_size)
            .with_max_pages(self.max_pages)
            .indexer_config(self.indexer_config);
        if let Some(after) = self.after {
            scan = scan.with_after(after);
        }
        let page = scan.run(env)?;
        let transactions = page
            .transactions
            .iter()
            .map(|transaction| {
                TransactionAudit {
                    auditor: self.auditor,
                    transaction,
                    assets,
                }
                .run_with_mode(self.mode)
            })
            .collect::<Result<_, _>>()?;
        Ok(AuditedPage {
            transactions,
            next: page.next,
        })
    }
}
