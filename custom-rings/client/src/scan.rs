//! Photon matches the auditor tag on outputs and messages alike, the message match is re-applied.

use std::{
    collections::HashMap,
    future::Future,
    num::{NonZeroU32, NonZeroUsize},
};

use custom_ring_interface::RingMode;
use solana_address::Address;
use zolana_client::{next_page, AsyncRpc, ClientError, IndexerRpcConfig};
use zolana_keypair::{X25519Keypair, X25519Pubkey};
use zolana_transaction::{AssetRegistry, ShieldedTransaction};

use crate::{
    decrypt::TransactionAudit,
    encryption::auditor_view_tag,
    origin::{RingOrigin, TransactionOrigin},
    types::{AuditedTransaction, KnownNote},
    AuditError,
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

/// Reads until the frontier or the cap, a stalled cursor or a frontierless terminal page fails.
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
        let (page, next_cursor, scanned_through) = fetch(cursor.clone()).await?;
        transactions.extend(page);
        read += 1;
        cursor = PageEnd {
            next_cursor,
            scanned_through,
        }
        .next(&cursor)?;
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

pub(crate) struct PageEnd {
    pub next_cursor: Option<Vec<u8>>,
    pub scanned_through: Option<Vec<u8>>,
}

impl PageEnd {
    /// `None` only past a page that states its scan frontier.
    pub(crate) fn next(self, cursor: &Option<Vec<u8>>) -> Result<Option<Vec<u8>>, AuditError> {
        match next_page(cursor, self.next_cursor, &self.scanned_through)? {
            None if self.scanned_through.is_none() => Err(AuditError::ScanFrontierMissing),
            next => Ok(next),
        }
    }
}

pub(crate) const DEFAULT_PAGE_SIZE: NonZeroU32 = NonZeroU32::new(100).unwrap();
pub(crate) const DEFAULT_MAX_PAGES: NonZeroUsize = NonZeroUsize::new(32).unwrap();

/// A confirmed ring transfer without its mandatory disclosure fails the scan.
#[must_use = "run or discard the scan explicitly"]
pub struct RingScan {
    ring_program_id: Address,
    auditor_key: X25519Pubkey,
    mode: RingMode,
    cursor: Option<Vec<u8>>,
    page_size: NonZeroU32,
    max_pages: NonZeroUsize,
    indexer_config: Option<IndexerRpcConfig>,
    known: HashMap<[u8; 32], KnownNote>,
    escrowed: HashMap<[u8; 32], [u8; 32]>,
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
            known: HashMap::new(),
            escrowed: HashMap::new(),
        }
    }

    /// The rail a ring `Transact` frame parses under.
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

    /// Notes opened before by commitment, earlier pages and [`crate::CreatedNotes`] alike.
    pub fn with_known_notes(mut self, notes: HashMap<[u8; 32], KnownNote>) -> Self {
        self.known = notes;
        self
    }

    /// Each owner key's nullifier key as the ring's escrow records hold it.
    pub fn with_escrowed_keys(mut self, keys: HashMap<[u8; 32], [u8; 32]>) -> Self {
        self.escrowed = keys;
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
        let page = self.confirmed(indexer, origin).await?;
        Ok(ScanPage {
            transactions: page
                .transactions
                .into_iter()
                .map(|(transaction, _)| transaction)
                .collect(),
            next_cursor: page.next_cursor,
        })
    }

    /// An input resolves within the page and the known notes.
    pub async fn audit<I: AsyncRpc, O: TransactionOrigin>(
        mut self,
        auditor: &X25519Keypair,
        indexer: &I,
        origin: &O,
        assets: &AssetRegistry,
    ) -> Result<AuditedPage, AuditError> {
        self.auditor_key = auditor.pubkey();
        let mode = self.mode;
        let mut known = core::mem::take(&mut self.known);
        let escrowed = core::mem::take(&mut self.escrowed);
        let page = self.confirmed(indexer, origin).await?;
        let mut transactions = Vec::with_capacity(page.transactions.len());
        for (transaction, confirmed) in &page.transactions {
            let trees = confirmed.event.input_tree_ids(transaction);
            let audited = TransactionAudit::new(transaction, confirmed.disclosure_layout(mode)?)
                .with_input_trees(&trees)?
                .with_known_notes(&known)
                .with_escrowed_keys(&escrowed)
                .run(auditor, assets)?;
            known.extend(audited.notes());
            transactions.push(audited);
        }
        Ok(ScanPage {
            transactions,
            next_cursor: page.next_cursor,
        })
    }

    /// The page's ring transfers that require an audit, each bound to its confirmed event.
    pub(crate) async fn confirmed<I: AsyncRpc, O: TransactionOrigin>(
        self,
        indexer: &I,
        origin: &O,
    ) -> Result<ScanPage<(ShieldedTransaction, RingOrigin)>, AuditError> {
        let view_tag = auditor_view_tag(&self.auditor_key);
        let (page, _) = pages(self.cursor, self.max_pages, |cursor| async move {
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
        let mut invoked = HashMap::<_, RingOrigin>::new();
        let mut transactions = Vec::new();
        for mut tx in page.transactions {
            let event_index = tx.event_index.ok_or(AuditError::MissingEventIndex)?;
            let key = (tx.tx_signature, event_index);
            let confirmed = match invoked.get(&key) {
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
                transactions.push((tx, confirmed));
            }
        }
        Ok(ScanPage {
            transactions,
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
    async fn a_terminal_page_without_a_frontier_fails_the_scan() {
        let served = [(Some(vec![1]), None), (None, None)];
        assert!(matches!(
            read(&served, 4).await,
            Err(AuditError::ScanFrontierMissing)
        ));
    }

    #[tokio::test]
    async fn a_terminal_page_with_a_frontier_completes_the_scan() {
        let served = [(Some(vec![1]), None), (None, Some(vec![1]))];
        let (page, read) = read(&served, 4).await.unwrap();
        assert_eq!((page.next_cursor, read), (None, 2));
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
