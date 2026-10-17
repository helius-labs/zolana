//! The auditor scans for its view tag, which Photon matches on output and message tags alike,
//! so the message match is re-applied and each match is attributed through its call stack.

use std::{
    collections::HashMap,
    future::Future,
    num::{NonZeroU32, NonZeroUsize},
};

use custom_ring_interface::RingMode;
use solana_address::Address;
use zolana_client::{next_page, AsyncRpc, ClientError, IndexerRpcConfig};
use zolana_keypair::{X25519Pubkey, X25519Secret};
use zolana_transaction::{AssetRegistry, ShieldedTransaction};

use crate::{
    decrypt::TransactionAudit, encryption::auditor_view_tag, origin::TransactionOrigin,
    types::AuditedTransaction, AuditError,
};

/// One bounded read, `next_cursor` is live only when the page cap stopped it.
pub struct ScanPage<T> {
    pub transactions: Vec<T>,
    pub next_cursor: Option<Vec<u8>>,
}

pub type RingScanPage = ScanPage<ShieldedTransaction>;
pub type AuditedPage = ScanPage<AuditedTransaction>;

/// One indexer page with its transactions, the next cursor and where the scan reached.
pub(crate) type Page = (Vec<ShieldedTransaction>, Option<Vec<u8>>, Option<Vec<u8>>);

/// Reads from `cursor` until `scanned_through` or the cap, a cursor that does not move fails.
pub(crate) async fn pages<F, Fut>(
    mut cursor: Option<Vec<u8>>,
    max_pages: NonZeroUsize,
    mut fetch: F,
) -> Result<(RingScanPage, usize), AuditError>
where
    F: FnMut(Option<Vec<u8>>) -> Fut,
    Fut: Future<Output = Result<Page, ClientError>>,
{
    let (mut transactions, mut read) = (Vec::new(), 0);
    loop {
        let (page, next, scanned_through) = fetch(cursor.clone()).await?;
        transactions.extend(page);
        read += 1;
        cursor = next_page(&cursor, next, &scanned_through)?;
        if cursor.is_none() || read == max_pages.get() {
            let next_cursor = cursor;
            return Ok((
                ScanPage {
                    transactions,
                    next_cursor,
                },
                read,
            ));
        }
    }
}

pub(crate) const DEFAULT_PAGE_SIZE: NonZeroU32 = NonZeroU32::new(100).unwrap();
const DEFAULT_MAX_PAGES: NonZeroUsize = NonZeroUsize::new(32).unwrap();

/// Confirmed ring transfers in the auditor tag scan. Missing mandatory disclosure fails closed.
#[must_use = "run or discard the scan explicitly"]
pub struct RingScan {
    ring_program_id: Address,
    auditor_key: X25519Pubkey,
    mode: RingMode,
    cursor: Option<Vec<u8>>,
    page_size: NonZeroU32,
    max_pages: NonZeroUsize,
    indexer_config: Option<IndexerRpcConfig>,
}

impl RingScan {
    pub fn new(ring_program_id: Address, auditor_key: X25519Pubkey) -> Self {
        Self {
            ring_program_id,
            auditor_key,
            mode: RingMode::Off,
            cursor: None,
            page_size: DEFAULT_PAGE_SIZE,
            max_pages: DEFAULT_MAX_PAGES,
            indexer_config: None,
        }
    }

    /// The ring's mode selects the disclosure layout an audit parses.
    pub fn with_mode(mut self, mode: RingMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_cursor(mut self, cursor: Vec<u8>) -> Self {
        self.cursor = Some(cursor);
        self
    }

    pub fn with_page_size(mut self, page_size: NonZeroU32) -> Self {
        self.page_size = page_size;
        self
    }

    pub fn with_max_pages(mut self, max_pages: NonZeroUsize) -> Self {
        self.max_pages = max_pages;
        self
    }

    /// Every page waits until the indexer has persisted `config.require_slot`.
    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.indexer_config = Some(config);
        self
    }

    pub(crate) fn indexer_config(mut self, config: Option<IndexerRpcConfig>) -> Self {
        self.indexer_config = config;
        self
    }

    pub async fn run<I: AsyncRpc, O: TransactionOrigin>(
        self,
        indexer: &I,
        origin: &O,
    ) -> Result<RingScanPage, AuditError> {
        let view_tag = auditor_view_tag(&self.auditor_key);
        let (mut page, _) = pages(self.cursor, self.max_pages, |cursor| async move {
            let page = indexer
                .get_shielded_transactions_by_tags(
                    vec![view_tag],
                    cursor,
                    Some(self.page_size.get()),
                    self.indexer_config,
                )
                .await?;
            Ok((page.transactions, page.next_cursor, page.scanned_through))
        })
        .await?;
        let mut invoked = HashMap::<_, crate::RingOrigin>::new();
        let mut transactions = Vec::new();
        for mut tx in page.transactions {
            let event_index = tx.event_index.ok_or(AuditError::MissingEventIndex)?;
            let key = (tx.tx_signature, event_index);
            let confirmed: crate::RingOrigin = match invoked.get(&key) {
                Some(known) => known.clone(),
                None => {
                    let origin = origin
                        .origin(tx.tx_signature, event_index, self.ring_program_id)
                        .await?;
                    invoked.entry(key).or_insert(origin).clone()
                }
            };
            if confirmed.requires_audit() {
                confirmed.bind_transaction(&mut tx, self.ring_program_id)?;
                if !tx
                    .messages
                    .iter()
                    .any(|message| message.view_tag == view_tag)
                {
                    return Err(AuditError::MissingAuditorMessage);
                }
                transactions.push(tx);
            }
        }
        page.transactions = transactions;
        Ok(page)
    }

    /// Scans the tag of `auditor` and opens every match with it.
    pub async fn audit<I: AsyncRpc, O: TransactionOrigin>(
        mut self,
        auditor: &X25519Secret,
        indexer: &I,
        origin: &O,
        assets: &AssetRegistry,
    ) -> Result<AuditedPage, AuditError> {
        self.auditor_key = auditor.pubkey();
        let mode = self.mode;
        let page = self.run(indexer, origin).await?;
        Ok(ScanPage {
            transactions: page
                .transactions
                .iter()
                .map(|transaction| {
                    TransactionAudit {
                        auditor,
                        transaction,
                        assets,
                    }
                    .run_with_mode(mode)
                })
                .collect::<Result<_, _>>()?,
            next_cursor: page.next_cursor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Per page, its next cursor and where the scan reached.
    type Served = (Option<Vec<u8>>, Option<Vec<u8>>);

    /// Serves `pages_served` in order, a cursor names the page index.
    async fn read(
        pages_served: &[Served],
        max_pages: usize,
    ) -> Result<(RingScanPage, usize), AuditError> {
        let max_pages = NonZeroUsize::new(max_pages).unwrap();
        pages(None, max_pages, |cursor| async move {
            let index = cursor.map_or(0, |cursor| usize::from(cursor[0]));
            let (next, scanned_through) = pages_served[index].clone();
            Ok((Vec::new(), next, scanned_through))
        })
        .await
    }

    #[tokio::test]
    async fn the_last_page_at_the_cap_completes_the_read() {
        let served = [(Some(vec![1]), None), (Some(vec![2]), Some(vec![2]))];
        let (page, read) = read(&served, 2).await.unwrap();
        assert_eq!((page.next_cursor, read), (None, 2));
    }

    #[tokio::test]
    async fn the_cap_returns_the_live_cursor() {
        let served = [(Some(vec![1]), None), (Some(vec![2]), None)];
        let (page, read) = read(&served, 2).await.unwrap();
        assert_eq!((page.next_cursor, read), (Some(vec![2]), 2));
    }

    #[tokio::test]
    async fn a_cursor_that_does_not_move_fails() {
        let served = [(Some(vec![1]), None), (Some(vec![1]), None)];
        assert!(matches!(
            read(&served, 4).await,
            Err(AuditError::Client(ClientError::IndexerCursorNotAdvanced))
        ));
    }
}
