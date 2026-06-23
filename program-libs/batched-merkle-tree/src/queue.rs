use crate::zero_copy::BoundedVecView;
use zolana_bloom_filter::BloomFilter;
use zolana_merkle_tree_metadata::QueueType;

use super::batch::BatchState;
use crate::{errors::BatchedMerkleTreeError, queue_batch_metadata::QueueBatches};

/// Insert a value into the current batch.
/// - Input & address queues: Insert into bloom filter & hash chain.
/// - Output queue: Insert into value vec & hash chain.
///
/// Steps:
/// 1. Check if the current batch is ready.
///    1.1. If the current batch is inserted, clear the batch.
/// 2. Insert value into the current batch.
/// 3. If batch is full, increment currently_processing_batch_index.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub(crate) fn insert_into_current_queue_batch<const NUM_ITERS: usize, const BYTES: usize>(
    queue_type: u64,
    batch_metadata: &mut QueueBatches,
    value_vecs: &mut [BoundedVecView<'_>],
    bloom_filters: Option<&mut [BloomFilter<NUM_ITERS, BYTES>; 2]>,
    hash_chain_stores: &mut [BoundedVecView<'_>],
    hash_chain_value: &[u8; 32],
    bloom_filter_value: Option<&[u8; 32]>,
    current_index: Option<u64>,
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
            // Clear the batch if it is inserted.

            // If a batch contains a bloom filter it must be zeroed by a forester.
            if queue_type != QueueType::OutputStateV2 as u64
                && !current_batch.bloom_filter_is_zeroed()
            {
                return Err(BatchedMerkleTreeError::BloomFilterNotZeroed);
            }
            // Advance the state to fill and reset the number of inserted elements.
            // If Some(current_index) set it as start index.
            // Reset, sequence number, root index, bloom filter zeroed, num_inserted_zkps
            // start_slot, start_slot_is_set.
            current_batch.advance_state_to_fill(current_index)?;
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
    let queue_type = QueueType::from(queue_type);
    match queue_type {
        QueueType::InputStateV2 | QueueType::AddressV2 => {
            let hash_chain_store = hash_chain_stores
                .get_mut(batch_index)
                .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?;
            current_batch.insert(
                bloom_filter_value.unwrap(),
                hash_chain_value,
                bloom_filters.ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?,
                hash_chain_store.data,
                batch_index,
                current_slot,
            )?;
            // Keep the bounded hash-chain length header consistent with upstream:
            // length == number of hash-chain slots written so far.
            *hash_chain_store.length = current_batch.get_hash_chain_store_len();
        }
        QueueType::OutputStateV2 => {
            let value_store = value_vecs
                .get_mut(batch_index)
                .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?;
            let hash_chain_store = hash_chain_stores
                .get_mut(batch_index)
                .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?;
            current_batch.store_and_hash_value(
                hash_chain_value,
                value_store.data,
                hash_chain_store.data,
                current_slot,
            )?;
            // Length headers: value vec holds every inserted element, hash chain
            // holds one slot per (full or in-progress) zkp batch.
            *value_store.length = current_batch.get_num_inserted_elements();
            *hash_chain_store.length = current_batch.get_hash_chain_store_len();
        }
    };

    // 3. If batch is full, increment currently_processing_batch_index.
    batch_metadata.increment_currently_processing_batch_index_if_full()?;

    Ok(())
}
