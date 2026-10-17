//! Confirmed blocks of a bounded slot range, in slot order, each linked to the
//! block before it by slot and hash.
//!
//! Unlike the tip-following poller, a range does not retry forever: a fetch
//! that still fails after a few quick attempts, or a broken link, ends it at
//! that position, after every block before it, so the caller can commit what
//! it applied and decide when to try again.

use std::{ops::RangeInclusive, sync::Arc, time::Duration};

use async_stream::stream;
use futures::{pin_mut, Stream, StreamExt};
use thiserror::Error;
use zolana_indexer_api::Hash;

use super::{poller::fetch_block, FetchError};

/// An RPC can briefly answer "block not available" for a slot it has just
/// confirmed; that is not worth ending a range over.
const FETCH_ATTEMPTS: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_millis(200);
use crate::{
    ingester::typedefs::block_info::{BlockInfo, BlockMetadata},
    rpc::RpcClient,
};

#[derive(Debug, Error)]
pub enum RangeError {
    #[error(transparent)]
    Fetch(#[from] FetchError),
    #[error(
        "block {slot} names parent {parent_slot} ({parent_blockhash}), \
         not the preceding block {previous_slot} ({previous_blockhash})"
    )]
    BrokenLink {
        slot: u64,
        parent_slot: u64,
        parent_blockhash: Hash,
        previous_slot: u64,
        previous_blockhash: Hash,
    },
}

/// The blocks in `slots`, `concurrency` fetches at a time. With `after`, the
/// first block must be its child; without it, the first block links to
/// nothing. Skipped slots yield nothing.
pub fn block_range(
    rpc_client: Arc<RpcClient>,
    after: Option<BlockMetadata>,
    slots: RangeInclusive<u64>,
    concurrency: usize,
) -> impl Stream<Item = Result<BlockInfo, RangeError>> + Send + 'static {
    stream! {
        let fetches = futures::stream::iter(slots)
            .map(move |slot| {
                let rpc_client = rpc_client.clone();
                async move { fetch_with_retries(&rpc_client, slot).await }
            })
            .buffered(concurrency.max(1));
        pin_mut!(fetches);
        let mut previous = after;
        while let Some(fetched) = fetches.next().await {
            let block = match fetched {
                Ok(Some(block)) => block,
                Ok(None) => continue,
                Err(error) => {
                    yield Err(error.into());
                    return;
                }
            };
            if let Err(error) = check_link(previous.as_ref(), &block.metadata) {
                yield Err(error);
                return;
            }
            previous = Some(block.metadata.clone());
            yield Ok(block);
        }
    }
}

/// `block` must be the child of `previous`, by slot and hash. Without a
/// previous block there is nothing to link to.
pub fn check_link(
    previous: Option<&BlockMetadata>,
    block: &BlockMetadata,
) -> Result<(), RangeError> {
    match previous {
        Some(previous) if !previous.is_parent_of(block) => Err(RangeError::BrokenLink {
            slot: block.slot,
            parent_slot: block.parent_slot,
            parent_blockhash: block.parent_blockhash.clone(),
            previous_slot: previous.slot,
            previous_blockhash: previous.blockhash.clone(),
        }),
        _ => Ok(()),
    }
}

/// Retries RPC failures only: a block that does not parse will not parse
/// on the next attempt either.
async fn fetch_with_retries(
    rpc_client: &RpcClient,
    slot: u64,
) -> Result<Option<BlockInfo>, FetchError> {
    let mut attempt = 1;
    loop {
        match fetch_block(rpc_client, slot).await {
            Err(FetchError::Rpc { .. }) if attempt < FETCH_ATTEMPTS => {
                attempt += 1;
                tokio::time::sleep(RETRY_DELAY).await;
            }
            fetched => return fetched,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::{server::ServerHandle, types::ErrorObjectOwned};
    use serde_json::{json, Value};
    use std::{collections::BTreeMap, sync::Mutex};

    fn hash(seed: u64) -> Hash {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&seed.to_be_bytes());
        Hash(bytes)
    }

    /// A block at `slot` whose parent is `parent`, hashed by slot.
    fn block(slot: u64, parent: u64) -> Value {
        json!({"blockhash": hash(slot).to_string(), "previousBlockhash": hash(parent).to_string(),
            "parentSlot": parent, "blockTime": slot, "blockHeight": slot, "transactions": []})
    }

    /// Serves `blocks`; a missing slot is skipped, and a slot in `failures`
    /// answers an error that many times before it is served.
    async fn chain(
        blocks: BTreeMap<u64, Value>,
        failures: BTreeMap<u64, u32>,
    ) -> (Arc<RpcClient>, ServerHandle) {
        let server = jsonrpsee::server::ServerBuilder::default()
            .build("127.0.0.1:0")
            .await
            .unwrap();
        let address = server.local_addr().unwrap();
        let mut module = jsonrpsee::RpcModule::new((blocks, Mutex::new(failures)));
        module
            .register_method("getBlock", |params, state, _| {
                let (slot, _): (u64, Value) = params.parse()?;
                let (blocks, failures) = state;
                if let Some(left) = failures
                    .lock()
                    .unwrap()
                    .get_mut(&slot)
                    .filter(|left| **left > 0)
                {
                    *left -= 1;
                    return Err(ErrorObjectOwned::owned(
                        -32000,
                        "archive failure",
                        None::<()>,
                    ));
                }
                blocks
                    .get(&slot)
                    .cloned()
                    .ok_or_else(|| ErrorObjectOwned::owned(-32007, "skipped", None::<()>))
            })
            .unwrap();
        (
            Arc::new(RpcClient::new(format!("http://{address}"))),
            server.start(module),
        )
    }

    fn anchor(slot: u64) -> BlockMetadata {
        BlockMetadata {
            slot,
            blockhash: hash(slot),
            ..Default::default()
        }
    }

    async fn collect(
        rpc: Arc<RpcClient>,
        after: Option<BlockMetadata>,
        slots: RangeInclusive<u64>,
    ) -> (Vec<u64>, Option<RangeError>) {
        let mut slots_seen = Vec::new();
        let range = block_range(rpc, after, slots, 3);
        pin_mut!(range);
        while let Some(block) = range.next().await {
            match block {
                Ok(block) => slots_seen.push(block.metadata.slot),
                Err(error) => {
                    assert!(range.next().await.is_none(), "an error ends the range");
                    return (slots_seen, Some(error));
                }
            }
        }
        (slots_seen, None)
    }

    #[tokio::test]
    async fn yields_linked_blocks_in_order_across_skipped_slots() {
        let blocks = BTreeMap::from([
            (11, block(11, 10)),
            (12, block(12, 11)),
            (15, block(15, 12)),
            (16, block(16, 15)),
        ]);
        let (rpc, handle) = chain(blocks, BTreeMap::new()).await;
        let (slots, error) = collect(rpc.clone(), Some(anchor(10)), 11..=20).await;
        assert_eq!(slots, [11, 12, 15, 16]);
        assert!(error.is_none());
        // Without an anchor the first block links to nothing.
        let (slots, error) = collect(rpc, None, 15..=16).await;
        assert_eq!(slots, [15, 16]);
        assert!(error.is_none());
        handle.stop().unwrap();
        handle.stopped().await;
    }

    #[tokio::test]
    async fn a_block_that_does_not_follow_the_previous_one_ends_the_range() {
        // 13 names 11 as its parent: the RPC called 12 a block of another fork.
        let blocks = BTreeMap::from([
            (11, block(11, 10)),
            (12, block(12, 11)),
            (13, block(13, 11)),
        ]);
        let (rpc, handle) = chain(blocks, BTreeMap::new()).await;
        let (slots, error) = collect(rpc.clone(), Some(anchor(10)), 11..=13).await;
        assert_eq!(slots, [11, 12]);
        assert!(matches!(
            error,
            Some(RangeError::BrokenLink {
                slot: 13,
                parent_slot: 11,
                previous_slot: 12,
                ..
            })
        ));

        // A different anchor hash is a break before the first block.
        let mut other = anchor(10);
        other.blockhash = hash(99);
        let (slots, error) = collect(rpc, Some(other), 11..=13).await;
        assert!(slots.is_empty());
        assert!(matches!(
            error,
            Some(RangeError::BrokenLink { slot: 11, .. })
        ));
        handle.stop().unwrap();
        handle.stopped().await;
    }

    #[tokio::test]
    async fn a_failed_fetch_ends_the_range_after_every_block_before_it() {
        let blocks = (11..=20)
            .map(|slot| (slot, block(slot, slot - 1)))
            .collect();
        let (rpc, handle) = chain(blocks, BTreeMap::from([(17, u32::MAX)])).await;
        let (slots, error) = collect(rpc, Some(anchor(10)), 11..=20).await;
        assert_eq!(slots, (11..=16).collect::<Vec<_>>());
        assert!(matches!(
            error,
            Some(RangeError::Fetch(FetchError::Rpc { slot: 17, .. }))
        ));
        handle.stop().unwrap();
        handle.stopped().await;
    }

    #[tokio::test]
    async fn a_fetch_that_recovers_within_its_attempts_does_not_end_the_range() {
        let blocks = (11..=14)
            .map(|slot| (slot, block(slot, slot - 1)))
            .collect();
        let failures = BTreeMap::from([(12, FETCH_ATTEMPTS - 1)]);
        let (rpc, handle) = chain(blocks, failures).await;
        let (slots, error) = collect(rpc, Some(anchor(10)), 11..=14).await;
        assert_eq!(slots, [11, 12, 13, 14]);
        assert!(error.is_none());
        handle.stop().unwrap();
        handle.stopped().await;
    }
}
