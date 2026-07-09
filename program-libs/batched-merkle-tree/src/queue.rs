use rings_bloom_filter::BloomFilter;

use super::batch::BatchState;
use crate::{
    errors::BatchedMerkleTreeError, queue_batch_metadata::QueueBatches, zero_copy::BoundedVecView,
};

/// Insert a value into the current input/address queue batch: into the bloom
/// filter (non-inclusion) and the hash chain.
///
/// Steps:
/// 1. Check if the current batch is ready. If it is inserted, clear it; a batch
///    with a bloom filter must be zeroed by a forester before reuse.
/// 2. Insert value into the current batch.
/// 3. If batch is full, increment currently_processing_batch_index.
#[allow(clippy::too_many_arguments)]
pub(crate) fn insert_into_current_queue_batch<const NUM_ITERS: usize, const BYTES: usize>(
    batch_metadata: &mut QueueBatches,
    bloom_filters: &mut [BloomFilter<NUM_ITERS, BYTES>; 2],
    hash_chain_stores: &mut [BoundedVecView<'_>],
    hash_chain_value: &[u8; 32],
    bloom_filter_value: &[u8; 32],
    current_slot: &u64,
) -> Result<(), BatchedMerkleTreeError> {
    let batch_index = batch_metadata.currently_processing_batch_index as usize;
    let current_batch = batch_metadata.get_current_batch_mut()?;
    // 1. Check that the current batch is ready (BatchState::Fill).
    //      1.1. If the current batch is inserted, clear the batch.
    {
        let clear_batch = current_batch.get_state() == BatchState::Inserted;
        if current_batch.get_state() == BatchState::Fill {
            // Do nothing, checking most common case first.
        } else if clear_batch {
            // The bloom filter must be zeroed by a forester before the batch is
            // reused, otherwise non-inclusion proofs would hit false positives.
            if !current_batch.bloom_filter_is_zeroed() {
                return Err(BatchedMerkleTreeError::BloomFilterNotZeroed);
            }
            // Advance the state to fill and reset the number of inserted elements.
            current_batch.advance_state_to_fill(None)?;
        } else {
            // We expect to insert into the current batch.
            #[cfg(feature = "log")]
            for batch in batch_metadata.batches.iter() {
                solana_msg::msg!("batch {:?}", batch);
            }
            return Err(BatchedMerkleTreeError::BatchNotReady);
        }
    }

    // 2. Insert value into the current batch.
    let hash_chain_store = hash_chain_stores
        .get_mut(batch_index)
        .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?;
    current_batch.insert(
        bloom_filter_value,
        hash_chain_value,
        bloom_filters,
        hash_chain_store.data,
        batch_index,
        current_slot,
    )?;
    // Keep the bounded hash-chain length header consistent with upstream:
    // length == number of hash-chain slots written so far.
    *hash_chain_store.length = current_batch.get_hash_chain_store_len();

    // 3. If batch is full, increment currently_processing_batch_index.
    batch_metadata.increment_currently_processing_batch_index_if_full()?;

    Ok(())
}
