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

use std::num::{NonZeroU32, NonZeroUsize};

use zolana_client::{RingShieldedTransactionsByTagRequest, Rpc};
use zolana_interface::pda;
use zolana_keypair::{P256Pubkey, ViewingKey};
use zolana_transaction::{AssetRegistry, RingAssociation, ShieldedTransaction};

use crate::{
    decrypt::TransactionAudit, encryption::auditor_view_tag, error::AuditError,
    types::AuditedTransaction,
};

pub struct RingScanPage {
    pub transactions: Vec<ShieldedTransaction>,
    pub next_cursor: Option<Vec<u8>>,
}

pub struct AuditedPage {
    pub transactions: Vec<AuditedTransaction>,
    pub next_cursor: Option<Vec<u8>>,
}

#[must_use = "run or discard the scan explicitly"]
/// Every indexed transaction that carries a message tagged for `auditor_key`.
///
/// The tag match is re-applied to the returned messages because the indexer
/// matches output tags and message tags.
pub struct RingScan<'a> {
    ring_program_id: solana_address::Address,
    auditor_key: &'a P256Pubkey,
    cursor: Option<Vec<u8>>,
    page_size: NonZeroU32,
    max_pages: NonZeroUsize,
}

#[must_use = "run or discard the audit explicitly"]
/// Scans and audits the bounded page range in one operation.
pub struct RingAudit<'a> {
    ring_program_id: solana_address::Address,
    auditor: &'a ViewingKey,
    cursor: Option<Vec<u8>>,
    page_size: NonZeroU32,
    max_pages: NonZeroUsize,
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
    pub fn new(ring_program_id: solana_address::Address, auditor_key: &'a P256Pubkey) -> Self {
        Self {
            ring_program_id,
            auditor_key,
            cursor: None,
            page_size: DEFAULT_PAGE_SIZE,
            max_pages: DEFAULT_MAX_PAGES,
        }
    }

    #[must_use = "use the updated scan"]
    pub fn with_cursor(mut self, cursor: Vec<u8>) -> Self {
        self.cursor = Some(cursor);
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

    pub fn run<I: Rpc>(self, indexer: &I) -> Result<RingScanPage, AuditError> {
        let view_tag = auditor_view_tag(self.auditor_key);
        let mut transactions = Vec::new();
        let mut cursor = self.cursor;
        for _ in 0..self.max_pages.get() {
            let mut request =
                RingShieldedTransactionsByTagRequest::new(view_tag, self.ring_program_id)
                    .with_limit(self.page_size);
            if let Some(cursor) = cursor.clone() {
                request = request.with_cursor(cursor);
            }
            let page = indexer.get_ring_shielded_transactions_by_tag(request)?;
            transactions.extend(page.transactions.into_iter().filter(|tx| {
                matches_expected_ring(&tx.ring, self.ring_program_id)
                    && tx
                        .messages
                        .iter()
                        .any(|message| message.view_tag == view_tag)
            }));
            let Some(next) = page.next_cursor else {
                return Ok(RingScanPage {
                    transactions,
                    next_cursor: None,
                });
            };
            if cursor.as_ref() == Some(&next) {
                return Err(AuditError::CursorNotAdvanced);
            }
            cursor = Some(next);
        }
        Ok(RingScanPage {
            transactions,
            next_cursor: cursor,
        })
    }
}

impl<'a> RingAudit<'a> {
    pub fn new(ring_program_id: solana_address::Address, auditor: &'a ViewingKey) -> Self {
        Self {
            ring_program_id,
            auditor,
            cursor: None,
            page_size: DEFAULT_PAGE_SIZE,
            max_pages: DEFAULT_MAX_PAGES,
        }
    }

    #[must_use = "use the updated audit"]
    pub fn with_cursor(mut self, cursor: Vec<u8>) -> Self {
        self.cursor = Some(cursor);
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

    pub fn run<I: Rpc>(
        self,
        indexer: &I,
        assets: &AssetRegistry,
    ) -> Result<AuditedPage, AuditError> {
        let auditor_key = self.auditor.pubkey();
        let mut scan = RingScan::new(self.ring_program_id, &auditor_key)
            .with_page_size(self.page_size)
            .with_max_pages(self.max_pages);
        if let Some(cursor) = self.cursor {
            scan = scan.with_cursor(cursor);
        }
        let page = scan.run(indexer)?;
        let transactions = page
            .transactions
            .iter()
            .map(|transaction| {
                TransactionAudit {
                    auditor: self.auditor,
                    transaction,
                    assets,
                }
                .run()
            })
            .collect::<Result<_, _>>()?;
        Ok(AuditedPage {
            transactions,
            next_cursor: page.next_cursor,
        })
    }
}

fn matches_expected_ring(
    ring: &RingAssociation,
    expected_program: solana_address::Address,
) -> bool {
    let expected_config = pda::ring_auth(&expected_program).0;
    match ring {
        RingAssociation::Unresolved { config } => *config == expected_config,
        RingAssociation::Resolved { config, program_id } => {
            *config == expected_config && *program_id == expected_program
        }
        RingAssociation::None => false,
    }
}
