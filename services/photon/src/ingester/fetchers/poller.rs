use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{atomic::Ordering, Arc, Mutex, PoisonError},
};

use async_stream::stream;
use cadence_macros::statsd_count;
use futures::{pin_mut, Stream, StreamExt};
use solana_transaction_status_client_types::TransactionDetails;

use crate::{
    ingester::typedefs::block_info::{parse_ui_confirmed_blocked, BlockInfo},
    metric,
    monitor::{start_latest_slot_updater, LATEST_SLOT},
    rpc::RpcClient,
};

/// A slot to fetch. `confirmed` means a later block named it as its parent:
/// the chain has a block there, whatever the RPC answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fetch {
    pub slot: u64,
    pub confirmed: bool,
}

type Refetches = Arc<Mutex<VecDeque<Fetch>>>;

/// Every slot from `start_slot` up to the chain tip, with refetches first.
fn get_slot_stream(
    rpc_client: Arc<RpcClient>,
    start_slot: u64,
    refetches: Refetches,
) -> impl Stream<Item = Fetch> {
    stream! {
        start_latest_slot_updater(rpc_client.clone()).await;
        let mut next_slot_to_fetch = start_slot;
        loop {
            let refetch = refetches
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front();
            if let Some(fetch) = refetch {
                yield fetch;
                continue;
            }
            if next_slot_to_fetch > LATEST_SLOT.load(Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                continue;
            }
            yield Fetch { slot: next_slot_to_fetch, confirmed: false };
            next_slot_to_fetch += 1;
        }
    }
}

pub fn get_block_poller_stream(
    rpc_client: Arc<RpcClient>,
    last_indexed_slot: u64,
    max_concurrent_block_fetches: usize,
) -> impl Stream<Item = Vec<BlockInfo>> {
    stream! {
        let start_slot = match last_indexed_slot {
            0 => 0,
            last_indexed_slot => last_indexed_slot + 1
        };
        let refetches: Refetches = Arc::default();
        let slot_stream = get_slot_stream(rpc_client.clone(), start_slot, refetches.clone());
        pin_mut!(slot_stream);
        let block_stream = slot_stream
            .map(|fetch| {
                let rpc_client = rpc_client.clone();
                async move { (fetch.slot, fetch_block_with_infinite_retries(rpc_client, fetch).await) }
            })
            .buffer_unordered(max_concurrent_block_fetches);
        pin_mut!(block_stream);
        let mut assembler = BlockAssembler::new(last_indexed_slot);
        while let Some((slot, block)) = block_stream.next().await {
            let Assembled { blocks, refetch } = assembler.push(slot, block);
            if !refetch.is_empty() {
                metric! {
                    statsd_count!(
                        "rpc_skipped_block_refetched",
                        i64::try_from(refetch.len()).unwrap_or(i64::MAX)
                    );
                }
                refetches
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend(refetch);
            }
            metric! {
                statsd_count!(
                    "rpc_block_emitted",
                    i64::try_from(blocks.len()).unwrap_or(i64::MAX)
                );
            }
            if !blocks.is_empty() {
                yield blocks;
            }
        }
    }
}

/// Fetched blocks put back in chain order. A block is released only when its
/// parent is the last block released, so blocks fetched out of order wait for
/// their parent, and a slot the RPC reported skipped is fetched again once a
/// later block names it as parent.
struct BlockAssembler {
    last_indexed_slot: u64,
    cache: BTreeMap<u64, BlockInfo>,
    /// Slots above `last_indexed_slot` the RPC reported skipped.
    skipped: BTreeSet<u64>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Assembled {
    /// The next blocks of the chain, in order.
    blocks: Vec<BlockInfo>,
    /// Slots to fetch again: the parent a block proved to exist, confirmed,
    /// then the skipped slots below it, which get one more try.
    refetch: Vec<Fetch>,
}

impl BlockAssembler {
    fn new(last_indexed_slot: u64) -> Self {
        Self {
            last_indexed_slot,
            cache: BTreeMap::new(),
            skipped: BTreeSet::new(),
        }
    }

    /// Records what the fetch of `slot` returned, `None` for a skipped slot.
    fn push(&mut self, slot: u64, block: Option<BlockInfo>) -> Assembled {
        let mut out = Assembled::default();
        match block {
            Some(block) => {
                self.cache.insert(slot, block);
            }
            None if slot > self.last_indexed_slot => {
                self.skipped.insert(slot);
            }
            None => {}
        }
        while let Some((&slot, block)) = self.cache.iter().next() {
            let parent = block.metadata.parent_slot;
            if parent == self.last_indexed_slot {
                if let Some(block) = self.cache.remove(&slot) {
                    out.blocks.push(block);
                }
                self.last_indexed_slot = slot;
                self.skipped = self.skipped.split_off(&(slot + 1));
            } else if slot <= self.last_indexed_slot {
                self.cache.remove(&slot);
            } else {
                if parent > self.last_indexed_slot && self.skipped.remove(&parent) {
                    out.refetch.push(Fetch {
                        slot: parent,
                        confirmed: true,
                    });
                    let below_parent: Vec<u64> = self.skipped.range(..parent).copied().collect();
                    for slot in below_parent {
                        self.skipped.remove(&slot);
                        out.refetch.push(Fetch {
                            slot,
                            confirmed: false,
                        });
                    }
                }
                break;
            }
        }
        out
    }
}

pub async fn fetch_block_with_infinite_retries(
    rpc_client: Arc<RpcClient>,
    fetch: Fetch,
) -> Option<BlockInfo> {
    let slot = fetch.slot;
    loop {
        match rpc_client.get_block(slot, TransactionDetails::Full).await {
            Ok(block) => {
                metric! {
                    statsd_count!("rpc_block_fetched", 1);
                }
                match parse_ui_confirmed_blocked(block, slot) {
                    Ok(block) => return Some(block),
                    Err(err) => {
                        log::error!("Failed to parse RPC block {}: {}", slot, err);
                        metric! {
                            statsd_count!("rpc_block_parse_failed", 1);
                        }
                    }
                }
            }
            Err(e) if e.is_slot_skipped() => {
                if fetch.confirmed {
                    metric! {
                        statsd_count!("rpc_skipped_block_contradicted", 1);
                    }
                    log::warn!(
                        "RPC reports slot {} skipped, but a later block names it as parent; retrying",
                        slot
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                metric! {
                    statsd_count!("rpc_skipped_block", 1);
                }
                log::info!("Skipped block: {}", slot);
                return None;
            }
            Err(_) => {
                metric! {
                    statsd_count!("rpc_block_fetch_failed", 1);
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingester::typedefs::block_info::BlockMetadata;

    fn block(slot: u64, parent_slot: u64) -> BlockInfo {
        BlockInfo {
            metadata: BlockMetadata {
                slot,
                parent_slot,
                ..Default::default()
            },
            transactions: Vec::new(),
        }
    }

    fn released(assembled: &Assembled) -> Vec<u64> {
        assembled
            .blocks
            .iter()
            .map(|block| block.metadata.slot)
            .collect()
    }

    const NOTHING: Assembled = Assembled {
        blocks: Vec::new(),
        refetch: Vec::new(),
    };

    #[test]
    fn releases_blocks_in_chain_order_once_their_parent_arrives() {
        let mut assembler = BlockAssembler::new(10);
        assert_eq!(assembler.push(12, Some(block(12, 11))), NOTHING);
        assert_eq!(assembler.push(13, Some(block(13, 12))), NOTHING);
        let out = assembler.push(11, Some(block(11, 10)));
        assert_eq!(released(&out), [11, 12, 13]);
        assert!(out.refetch.is_empty());
        assert_eq!(assembler.last_indexed_slot, 13);
    }

    #[test]
    fn a_slot_the_chain_skips_is_not_fetched_again() {
        let mut assembler = BlockAssembler::new(10);
        assert_eq!(assembler.push(11, None), NOTHING);
        let out = assembler.push(12, Some(block(12, 10)));
        assert_eq!(released(&out), [12]);
        assert!(out.refetch.is_empty());
        assert!(
            assembler.skipped.is_empty(),
            "skipped slots below the chain are forgotten"
        );
    }

    #[test]
    fn a_skipped_slot_a_later_block_names_as_parent_is_fetched_again() {
        let mut assembler = BlockAssembler::new(10);
        for slot in 11..=14 {
            assert_eq!(assembler.push(slot, None), NOTHING);
        }
        // The chain says slot 13 has a block; the RPC had said otherwise about 11 to 14.
        let out = assembler.push(15, Some(block(15, 13)));
        assert!(out.blocks.is_empty());
        assert_eq!(
            out.refetch,
            [
                Fetch {
                    slot: 13,
                    confirmed: true
                },
                Fetch {
                    slot: 11,
                    confirmed: false
                },
                Fetch {
                    slot: 12,
                    confirmed: false
                },
            ]
        );
        assert_eq!(assembler.skipped.iter().copied().collect::<Vec<_>>(), [14]);

        // The retried slots come back: 11 and 12 skipped for real, 13 with its block.
        assert_eq!(assembler.push(11, None), NOTHING);
        assert_eq!(assembler.push(12, None), NOTHING);
        let out = assembler.push(13, Some(block(13, 10)));
        assert_eq!(released(&out), [13, 15]);
        assert!(out.refetch.is_empty());
        assert!(assembler.skipped.is_empty());
    }

    #[test]
    fn a_contradicted_parent_is_fetched_again_only_once_per_proof() {
        let mut assembler = BlockAssembler::new(10);
        assert_eq!(assembler.push(11, None), NOTHING);
        let first = assembler.push(12, Some(block(12, 11)));
        assert_eq!(
            first.refetch,
            [Fetch {
                slot: 11,
                confirmed: true
            }]
        );
        // Another block above it changes nothing while 11 is in flight.
        assert_eq!(assembler.push(13, Some(block(13, 12))), NOTHING);
    }

    #[test]
    fn stale_and_repeated_blocks_are_dropped() {
        let mut assembler = BlockAssembler::new(10);
        assert_eq!(assembler.push(10, Some(block(10, 9))), NOTHING);
        assert_eq!(assembler.push(5, Some(block(5, 4))), NOTHING);
        assert_eq!(assembler.push(5, None), NOTHING);
        assert!(assembler.cache.is_empty());
        assert!(assembler.skipped.is_empty());
    }

    #[test]
    fn starts_from_genesis_when_nothing_was_indexed() {
        let mut assembler = BlockAssembler::new(0);
        assert_eq!(released(&assembler.push(0, Some(block(0, 0)))), [0]);
        assert_eq!(released(&assembler.push(1, Some(block(1, 0)))), [1]);
    }

    #[test]
    fn a_block_below_the_indexed_chain_waits_rather_than_forking() {
        let mut assembler = BlockAssembler::new(10);
        assert_eq!(assembler.push(12, Some(block(12, 8))), NOTHING);
        assert_eq!(assembler.cache.len(), 1);
    }
}
