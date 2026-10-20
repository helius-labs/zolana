//! `TagStream` against an in-memory indexer that pages as Photon does.

use std::{collections::BTreeSet, sync::Mutex};

use async_trait::async_trait;
use solana_signature::Signature;
use zolana_client::{
    AsyncRpc, ClientError, Context, GetShieldedTransactionsByTagsResponse, IndexerRpcConfig,
    OutputContext, OutputSlot, ShieldedTransaction, TagStream, DEFAULT_TAG_WINDOW,
};
use zolana_keypair::{viewing_key::ViewTag, KeypairError, ViewingKey};

/// Serves one undecryptable output per occupied index, two under a collision.
struct Indexer {
    outputs: Vec<ShieldedTransaction>,
    page_size: usize,
    queries: Mutex<Vec<Vec<ViewTag>>>,
}

impl Indexer {
    fn new(key: &ViewingKey, occupied: &[u64], collision: Option<u64>) -> Self {
        let outputs = occupied
            .iter()
            .chain(collision.iter())
            .enumerate()
            .map(|(nonce, index)| {
                let nonce = nonce as u8;
                ShieldedTransaction {
                    slot: u64::from(nonce),
                    tx_signature: Signature::from([nonce; 64]),
                    event_index: Some(0),
                    tx_viewing_pk: None,
                    salt: None,
                    output_slots: vec![OutputSlot {
                        view_tag: key.get_sender_view_tag(*index).unwrap(),
                        output_context: OutputContext {
                            hash: [nonce; 32],
                            tree_id: 0,
                            leaf_index: u64::from(nonce),
                        },
                        payload: vec![0xff; 8],
                    }],
                    messages: Vec::new(),
                    nullifiers: Vec::new(),
                    proofless: false,
                    ring_config: None,
                    ring_program_id: None,
                }
            })
            .collect();
        Self {
            outputs,
            page_size: 2,
            queries: Mutex::new(Vec::new()),
        }
    }

    fn queries(&self) -> usize {
        self.queries.lock().unwrap().len()
    }
}

#[async_trait]
impl AsyncRpc for Indexer {
    async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.queries.lock().unwrap().push(tags.clone());
        let matching: Vec<_> = self
            .outputs
            .iter()
            .filter(|tx| {
                tx.output_slots
                    .iter()
                    .any(|slot| tags.contains(&slot.view_tag))
            })
            .cloned()
            .collect();
        let start = cursor.map_or(0, |cursor| usize::from(cursor[0]));
        let len = matching.len();
        let transactions: Vec<_> = matching
            .into_iter()
            .skip(start)
            .take(self.page_size)
            .collect();
        Ok(GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: 0,
            },
            output_tree_id: Some(0),
            next_cursor: (!transactions.is_empty())
                .then(|| vec![(start + transactions.len()) as u8]),
            scanned_through: (transactions.len() < self.page_size).then(|| vec![len as u8]),
            transactions,
        })
    }
}

fn key() -> ViewingKey {
    ViewingKey::from_bytes(&[0x21; 32])
}

fn sender_tag(key: &ViewingKey) -> impl Fn(u64) -> Result<ViewTag, KeypairError> + '_ {
    move |index| key.get_sender_view_tag(index)
}

#[tokio::test]
async fn an_undecryptable_or_colliding_output_occupies_its_index() {
    let key = key();
    let indexer = Indexer::new(&key, &[0, 1, 2, 5], Some(1));
    let stream = TagStream::new(&indexer);
    assert_eq!(
        stream.occupied_indices(0, sender_tag(&key)).await.unwrap(),
        BTreeSet::from([0, 1, 2, 5])
    );
    assert_eq!(
        stream.first_free_index(0, sender_tag(&key)).await.unwrap(),
        3
    );
    assert_eq!(
        stream.first_free_index(4, sender_tag(&key)).await.unwrap(),
        4
    );
    assert_eq!(
        stream.first_free_index(5, sender_tag(&key)).await.unwrap(),
        6
    );
    // Five matches at two rows a page take three pages, one match one page.
    assert_eq!(indexer.queries(), 3 + 3 + 1 + 1);
}

#[tokio::test]
async fn a_full_window_moves_the_search_to_the_next_window() {
    let key = key();
    let occupied: Vec<u64> = (0..DEFAULT_TAG_WINDOW)
        .chain([DEFAULT_TAG_WINDOW + 1])
        .collect();
    let indexer = Indexer::new(&key, &occupied, None);
    let stream = TagStream::new(&indexer);
    assert_eq!(
        stream.first_free_index(0, sender_tag(&key)).await.unwrap(),
        DEFAULT_TAG_WINDOW
    );
    let queries = indexer.queries.lock().unwrap();
    let windows: Vec<BTreeSet<ViewTag>> = queries
        .iter()
        .map(|tags| tags.iter().copied().collect())
        .collect();
    let expected = |start: u64| {
        (start..start + DEFAULT_TAG_WINDOW)
            .map(|index| key.get_sender_view_tag(index).unwrap())
            .collect::<BTreeSet<_>>()
    };
    assert!(windows
        .iter()
        .all(|tags| tags.len() as u64 == DEFAULT_TAG_WINDOW));
    assert_eq!(windows[0], expected(0));
    assert_eq!(*windows.last().unwrap(), expected(DEFAULT_TAG_WINDOW));
}

#[tokio::test]
async fn an_empty_stream_is_free_at_its_start() {
    let key = key();
    let indexer = Indexer::new(&key, &[], None);
    let stream = TagStream::new(&indexer);
    assert_eq!(
        stream.first_free_index(0, sender_tag(&key)).await.unwrap(),
        0
    );
    assert_eq!(
        stream.first_free_index(70, sender_tag(&key)).await.unwrap(),
        70
    );
    assert!(stream
        .occupied_indices(0, sender_tag(&key))
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn an_exhausted_stream_is_an_error() {
    let key = key();
    let start = u64::MAX - DEFAULT_TAG_WINDOW + 1;
    let occupied: Vec<u64> = (start..=u64::MAX).collect();
    let indexer = Indexer::new(&key, &occupied, None);
    let stream = TagStream::new(&indexer);
    assert!(matches!(
        stream.first_free_index(start, sender_tag(&key)).await,
        Err(ClientError::TagStreamExhausted)
    ));
}
