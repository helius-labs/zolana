use super::batch::BatchState;
use crate::{
    constants::NUM_BATCHES, errors::BatchedMerkleTreeError, queue_batch_metadata::QueueBatches,
};

/// Insert a value into the current input/address queue batch's hash chain.
///
/// Steps:
/// 1. Check that the current batch is ready. If it is inserted, reuse it: its
///    coverage starts one rotation after its previous start.
/// 2. Insert value into the current batch.
/// 3. If batch is full, increment currently_processing_batch_index.
pub(crate) fn insert_into_current_queue_batch<const ZKP: usize>(
    batch_metadata: &mut QueueBatches,
    hash_chains: &mut [[[u8; 32]; ZKP]; NUM_BATCHES],
    value: &[u8; 32],
) -> Result<(), BatchedMerkleTreeError> {
    let batch_index = batch_metadata.currently_processing_batch_index as usize;
    let rotation = batch_metadata.rotation()?;
    let current_batch = batch_metadata.get_current_batch_mut()?;
    // 1. Check that the current batch is ready (BatchState::Fill).
    //      1.1. If the current batch is inserted, advance it to fill.
    match current_batch.checked_state()? {
        BatchState::Fill => {}
        BatchState::Inserted => {
            let start_index = current_batch
                .start_index
                .checked_add(rotation)
                .ok_or(BatchedMerkleTreeError::ArithmeticOverflow)?;
            current_batch.advance_state_to_fill(start_index)?;
        }
        BatchState::Full => {
            #[cfg(feature = "log")]
            solana_msg::msg!("current batch {:?} is full", current_batch);
            return Err(BatchedMerkleTreeError::BatchNotReady);
        }
    }

    // 2. Insert value into the current batch.
    let hash_chain = hash_chains
        .get_mut(batch_index)
        .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?;
    current_batch.add_to_hash_chain(value, hash_chain)?;

    // 3. If batch is full, increment currently_processing_batch_index.
    batch_metadata.increment_currently_processing_batch_index_if_full()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{batch::BatchState, constants::NUM_BATCHES};

    /// A reused batch must cover the queue index range one full rotation
    /// (`NUM_BATCHES * batch_size`) after its previous start, keeping the
    /// indexer-visible start_index consistent with the init-time invariant
    /// `start_index = batch_size * i + next_index`.
    #[test]
    fn test_reused_batch_start_index_advances_by_one_rotation() {
        let batch_size = 2;
        let zkp_batch_size = 2;
        let init_start_index = 1;
        QueueBatches::validate_configuration::<1>(batch_size, zkp_batch_size).unwrap();
        let mut batch_metadata =
            QueueBatches::new(batch_size, zkp_batch_size, init_start_index).unwrap();
        let mut hash_chains = [[[0u8; 32]; 1]; NUM_BATCHES];

        for i in 0..batch_size as u8 {
            insert_into_current_queue_batch(&mut batch_metadata, &mut hash_chains, &[i + 1; 32])
                .unwrap();
        }
        let batch = batch_metadata.batches.get_mut(0).unwrap();
        batch.mark_as_inserted_in_merkle_tree().unwrap();
        assert_eq!(batch.get_state(), BatchState::Inserted);
        let reclaimable_sequence = batch.reclaimable_sequence().unwrap();
        assert_eq!(reclaimable_sequence, init_start_index - 1 + batch_size);

        for i in 0..batch_size as u8 {
            insert_into_current_queue_batch(&mut batch_metadata, &mut hash_chains, &[i + 11; 32])
                .unwrap();
        }
        assert_eq!(batch_metadata.currently_processing_batch_index, 0);

        insert_into_current_queue_batch(&mut batch_metadata, &mut hash_chains, &[21; 32]).unwrap();
        let batch = batch_metadata.batches.first().unwrap();
        assert_eq!(batch.get_state(), BatchState::Fill);
        assert_eq!(
            batch.start_index,
            init_start_index + NUM_BATCHES as u64 * batch_size
        );
    }
}
