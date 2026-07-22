use zolana_bloom_filter::BloomFilter;

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
    // A batch reaches Inserted only after exactly batch_size insertions, so on
    // reuse its coverage starts one full rotation after its previous start.
    // Nothing in verify/apply reads batch start_index (the proof StartIndex is
    // derived from the tree next index); it is kept correct for indexers.
    let rotation = batch_metadata
        .num_batches
        .checked_mul(batch_metadata.batch_size)
        .ok_or(BatchedMerkleTreeError::ArithmeticOverflow)?;
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
            let start_index = current_batch
                .start_index
                .checked_add(rotation)
                .ok_or(BatchedMerkleTreeError::ArithmeticOverflow)?;
            current_batch.advance_state_to_fill(Some(start_index))?;
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

#[cfg(test)]
mod tests {
    use zolana_bloom_filter::BloomFilter;

    use super::*;
    use crate::batch::BatchState;

    const NUM_ITERS: usize = 3;
    const BLOOM_BYTES: usize = 128;

    fn insert(
        batch_metadata: &mut QueueBatches,
        bloom_filters: &mut [BloomFilter<NUM_ITERS, BLOOM_BYTES>; 2],
        hash_chain_lengths: &mut [u64; 2],
        hash_chain_data: &mut [[[u8; 32]; 1]; 2],
        value: &[u8; 32],
    ) -> Result<(), BatchedMerkleTreeError> {
        let [len0, len1] = hash_chain_lengths;
        let [data0, data1] = hash_chain_data;
        let mut hash_chain_stores = [
            BoundedVecView {
                length: len0,
                data: data0,
            },
            BoundedVecView {
                length: len1,
                data: data1,
            },
        ];
        insert_into_current_queue_batch(
            batch_metadata,
            bloom_filters,
            &mut hash_chain_stores,
            value,
            value,
            &1u64,
        )
    }

    /// A reused batch must cover the queue index range one full rotation
    /// (num_batches * batch_size) after its previous start, keeping the
    /// indexer-visible start_index consistent with the init-time invariant
    /// `start_index = batch_size * i + next_index`.
    #[test]
    fn test_reused_batch_start_index_advances_by_one_rotation() {
        let batch_size = 2;
        let zkp_batch_size = 2;
        let init_start_index = 1;
        let mut batch_metadata =
            QueueBatches::new_input_queue(batch_size, zkp_batch_size, init_start_index).unwrap();
        let mut bloom_filters = [BloomFilter::<NUM_ITERS, BLOOM_BYTES>::default(); 2];
        let mut hash_chain_lengths = [0u64; 2];
        let mut hash_chain_data = [[[0u8; 32]; 1]; 2];

        // Fill batch 0, mark it inserted into the tree, and zero its bloom filter.
        for i in 0..batch_size as u8 {
            insert(
                &mut batch_metadata,
                &mut bloom_filters,
                &mut hash_chain_lengths,
                &mut hash_chain_data,
                &[i + 1; 32],
            )
            .unwrap();
        }
        let batch = batch_metadata.batches.get_mut(0).unwrap();
        batch.mark_as_inserted_in_merkle_tree(1, 1, 10).unwrap();
        batch.set_bloom_filter_to_zeroed();
        assert_eq!(batch.get_state(), BatchState::Inserted);

        // Fill batch 1 so the current batch cycles back to batch 0.
        for i in 0..batch_size as u8 {
            insert(
                &mut batch_metadata,
                &mut bloom_filters,
                &mut hash_chain_lengths,
                &mut hash_chain_data,
                &[i + 11; 32],
            )
            .unwrap();
        }
        assert_eq!(batch_metadata.currently_processing_batch_index, 0);

        // The next insertion reuses batch 0: it is cleared and its start_index
        // advances by one full rotation.
        insert(
            &mut batch_metadata,
            &mut bloom_filters,
            &mut hash_chain_lengths,
            &mut hash_chain_data,
            &[21; 32],
        )
        .unwrap();
        let batch = batch_metadata.batches.first().unwrap();
        assert_eq!(batch.get_state(), BatchState::Fill);
        assert_eq!(
            batch.start_index,
            init_start_index + batch_metadata.num_batches * batch_size
        );
    }
}
