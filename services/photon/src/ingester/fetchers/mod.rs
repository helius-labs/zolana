use std::{sync::Arc, time::Duration};

use crate::{metric, rpc::RpcClient, rpc::RpcError};
use async_stream::stream;
use cadence_macros::statsd_count;
use futures::{pin_mut, Stream, StreamExt};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use super::{
    error::IngesterError,
    typedefs::block_info::{BlockInfo, BlockMetadata},
};

pub mod grpc;
pub mod poller;
pub mod range;

use grpc::get_grpc_stream_with_rpc_fallback;
use poller::get_block_poller_stream;

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("cannot fetch block {slot}: {source}")]
    Rpc {
        slot: u64,
        #[source]
        source: RpcError,
    },
    #[error("getBlock for slot {slot} missed its {limit:?} deadline")]
    TimedOut { slot: u64, limit: Duration },
    #[error("cannot parse block {slot}: {source}")]
    Parse {
        slot: u64,
        #[source]
        source: IngesterError,
    },
}

pub struct BlockStreamConfig {
    pub rpc_client: Arc<RpcClient>,
    pub geyser_url: Option<String>,
    pub max_concurrent_block_fetches: usize,
    pub last_indexed_slot: u64,
}

impl BlockStreamConfig {
    /// Blocks from `last_indexed_slot` on, following the chain tip. Fetching
    /// runs in its own task, so it continues while the caller writes a batch.
    pub fn load_block_stream(&self) -> impl Stream<Item = Vec<BlockInfo>> {
        let grpc_stream = self.geyser_url.as_ref().and_then(|geyser_url| {
            let auth_header = match std::env::var("GRPC_X_TOKEN") {
                Ok(auth_header) => auth_header,
                Err(err) => {
                    log::error!(
                        "GRPC_X_TOKEN is required when grpc_url is configured; falling back to RPC polling: {}",
                        err
                    );
                    return None;
                }
            };
            Some(get_grpc_stream_with_rpc_fallback(
                    geyser_url.clone(),
                    auth_header,
                    self.rpc_client.clone(),
                    self.last_indexed_slot,
                    self.max_concurrent_block_fetches,
                ))
        });

        let poller_stream = if grpc_stream.is_none() {
            Some(get_block_poller_stream(
                self.rpc_client.clone(),
                self.last_indexed_slot,
                self.max_concurrent_block_fetches,
            ))
        } else {
            None
        };

        let blocks = stream! {
            if let Some(grpc_stream) = grpc_stream {
                pin_mut!(grpc_stream);
                while let Some(blocks) = grpc_stream.next().await {
                    yield blocks;
                }
            }

            if let Some(poller_stream) = poller_stream {
                pin_mut!(poller_stream);
                while let Some(blocks) = poller_stream.next().await {
                    yield blocks;
                }
            }
        };
        spawn_stream(
            report_parent_hash_mismatches(blocks),
            self.max_concurrent_block_fetches,
        )
    }
}

/// Drives `stream` in its own task, `capacity` items ahead of the caller. The
/// task ends at the first item the caller no longer receives.
pub fn spawn_stream<T: Send + 'static>(
    stream: impl Stream<Item = T> + Send + 'static,
    capacity: usize,
) -> ReceiverStream<T> {
    let (sender, receiver) = mpsc::channel(capacity.max(1));
    tokio::spawn(async move {
        pin_mut!(stream);
        while let Some(item) = stream.next().await {
            if sender.send(item).await.is_err() {
                break;
            }
        }
    });
    ReceiverStream::new(receiver)
}

/// Both fetchers link a block to its parent by slot only. A block whose parent
/// hash differs from the block released before it means the chain or the RPC
/// moved under us; for now that is counted and logged, not acted on.
fn report_parent_hash_mismatches(
    blocks: impl Stream<Item = Vec<BlockInfo>>,
) -> impl Stream<Item = Vec<BlockInfo>> {
    stream! {
        pin_mut!(blocks);
        let mut previous: Option<BlockMetadata> = None;
        while let Some(batch) = blocks.next().await {
            for block in &batch {
                if let Some(previous) = &previous {
                    if names_another_parent(previous, &block.metadata) {
                        metric! {
                            statsd_count!("block_parent_hash_mismatch", 1);
                        }
                        log::error!(
                            "Block {} names parent {} with hash {}, but the block indexed at {} is {}",
                            block.metadata.slot,
                            block.metadata.parent_slot,
                            block.metadata.parent_blockhash,
                            previous.slot,
                            previous.blockhash
                        );
                    }
                }
                previous = Some(block.metadata.clone());
            }
            yield batch;
        }
    }
}

fn names_another_parent(previous: &BlockMetadata, block: &BlockMetadata) -> bool {
    block.parent_slot == previous.slot && block.parent_blockhash != previous.blockhash
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_indexer_api::Hash;

    fn block(slot: u64, parent_slot: u64, hash: u8, parent_hash: u8) -> BlockInfo {
        BlockInfo {
            metadata: BlockMetadata {
                slot,
                parent_slot,
                blockhash: Hash([hash; 32]),
                parent_blockhash: Hash([parent_hash; 32]),
                ..Default::default()
            },
            transactions: Vec::new(),
        }
    }

    #[test]
    fn only_a_different_hash_for_the_same_parent_slot_is_a_mismatch() {
        let parent = block(10, 9, 1, 0).metadata;
        assert!(!names_another_parent(
            &parent,
            &block(11, 10, 2, 1).metadata
        ));
        assert!(names_another_parent(&parent, &block(11, 10, 2, 7).metadata));
        // The fetchers never release a block whose parent slot is not the last
        // one; a different slot is theirs to handle, not a hash mismatch.
        assert!(!names_another_parent(
            &parent,
            &block(12, 11, 2, 7).metadata
        ));
    }

    #[tokio::test]
    async fn mismatches_are_reported_without_changing_the_batches() {
        let batches = vec![
            vec![block(10, 9, 1, 0), block(11, 10, 2, 1)],
            vec![block(12, 11, 3, 9)],
        ];
        let out: Vec<Vec<u64>> = report_parent_hash_mismatches(futures::stream::iter(batches))
            .map(|batch| batch.iter().map(|block| block.metadata.slot).collect())
            .collect()
            .await;
        assert_eq!(out, [vec![10, 11], vec![12]]);
    }

    #[tokio::test]
    async fn a_spawned_stream_keeps_order_and_stops_with_its_receiver() {
        let all: Vec<u32> = spawn_stream(futures::stream::iter(0..100), 4)
            .collect()
            .await;
        assert_eq!(all, (0..100).collect::<Vec<_>>());

        let (dropped, mut dropped_rx) = mpsc::channel::<()>(1);
        let endless = stream! {
            let _guard = dropped;
            let mut n = 0u64;
            loop {
                yield n;
                n += 1;
            }
        };
        let first: Vec<u64> = spawn_stream(endless, 2).take(3).collect().await;
        assert_eq!(first, [0, 1, 2]);
        // The task drops the stream, and with it the guard, once nobody receives.
        assert!(dropped_rx.recv().await.is_none());
    }
}
