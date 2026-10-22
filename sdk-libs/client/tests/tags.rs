//! The page loop of the indexer reads against an indexer that cycles its cursors.

use std::sync::Mutex;

use async_trait::async_trait;
use zolana_client::{
    AsyncRpc, ClientError, Context, GetShieldedTransactionsByTagsResponse, IndexerRpcConfig,
};

/// Answers every page with the next cursor of a two-cursor cycle.
struct CyclingCursors {
    pages: Mutex<u8>,
}

#[async_trait]
impl AsyncRpc for CyclingCursors {
    async fn get_shielded_transactions_by_tags(
        &self,
        _tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        let mut pages = self.pages.lock().unwrap();
        *pages += 1;
        if *pages > 8 {
            return Err(ClientError::Indexer("the loop pages on".to_owned()));
        }
        Ok(GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: 0,
            },
            output_tree_id: Some(0),
            transactions: Vec::new(),
            next_cursor: Some(vec![1 + *pages % 2]),
            scanned_through: None,
        })
    }
}

#[tokio::test]
async fn a_cursor_seen_before_in_the_page_loop_is_refused() {
    let indexer = CyclingCursors {
        pages: Mutex::new(0),
    };
    let read = zolana_client::IndexerReads::new(&indexer)
        .transactions(&[[0; 32]])
        .await;
    assert!(matches!(read, Err(ClientError::IndexerCursorNotAdvanced)));
    assert_eq!(*indexer.pages.lock().unwrap(), 3);
}
