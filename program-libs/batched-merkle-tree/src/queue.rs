use super::batch::BatchState;
use crate::{
    errors::BatchedMerkleTreeError, queue_batch_metadata::QueueBatches, zero_copy::BoundedVecView,
};

pub(crate) fn insert_into_current_queue_batch(
    batch_metadata: &mut QueueBatches,
    hash_chain_stores: &mut [BoundedVecView<'_>],
    value: &[u8; 32],
    close_before_index: u64,
) -> Result<(), BatchedMerkleTreeError> {
    let batch_index = batch_metadata.currently_processing_batch_index as usize;
    let rotation = batch_metadata.rotation()?;
    let current_batch = batch_metadata.get_current_batch_mut()?;
    match current_batch.checked_state()? {
        BatchState::Fill => {}
        BatchState::Inserted => {
            if !current_batch.is_reclaimable(close_before_index) {
                return Err(BatchedMerkleTreeError::BatchNotReclaimable);
            }
            let start_index = current_batch
                .start_index
                .checked_add(rotation)
                .ok_or(BatchedMerkleTreeError::ArithmeticOverflow)?;
            current_batch.advance_state_to_fill(Some(start_index))?;
        }
        BatchState::Full => {
            #[cfg(feature = "log")]
            solana_msg::msg!("current batch {:?} is full", current_batch);
            return Err(BatchedMerkleTreeError::BatchNotReady);
        }
    }

    let hash_chain_store = hash_chain_stores
        .get_mut(batch_index)
        .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?;
    current_batch.add_to_hash_chain(value, hash_chain_store.data)?;
    *hash_chain_store.length = current_batch.get_hash_chain_store_len();

    batch_metadata.increment_currently_processing_batch_index_if_full()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::BatchState;

    fn insert(
        batch_metadata: &mut QueueBatches,
        hash_chain_lengths: &mut [u64; 2],
        hash_chain_data: &mut [[[u8; 32]; 1]; 2],
        value: &[u8; 32],
        close_before_index: u64,
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
            &mut hash_chain_stores,
            value,
            close_before_index,
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
        let mut hash_chain_lengths = [0u64; 2];
        let mut hash_chain_data = [[[0u8; 32]; 1]; 2];

        for i in 0..batch_size as u8 {
            insert(
                &mut batch_metadata,
                &mut hash_chain_lengths,
                &mut hash_chain_data,
                &[i + 1; 32],
                0,
            )
            .unwrap();
        }
        let batch = batch_metadata.batches.get_mut(0).unwrap();
        batch.mark_as_inserted_in_merkle_tree(1, 1, 10).unwrap();
        assert_eq!(batch.get_state(), BatchState::Inserted);
        let reclaimable_sequence = batch.reclaimable_sequence().unwrap();
        assert_eq!(reclaimable_sequence, init_start_index - 1 + batch_size);

        for i in 0..batch_size as u8 {
            insert(
                &mut batch_metadata,
                &mut hash_chain_lengths,
                &mut hash_chain_data,
                &[i + 11; 32],
                0,
            )
            .unwrap();
        }
        assert_eq!(batch_metadata.currently_processing_batch_index, 0);

        let before = batch_metadata;
        assert_eq!(
            insert(
                &mut batch_metadata,
                &mut hash_chain_lengths,
                &mut hash_chain_data,
                &[21; 32],
                reclaimable_sequence - 1,
            )
            .unwrap_err(),
            BatchedMerkleTreeError::BatchNotReclaimable
        );
        assert_eq!(batch_metadata, before);

        insert(
            &mut batch_metadata,
            &mut hash_chain_lengths,
            &mut hash_chain_data,
            &[21; 32],
            reclaimable_sequence,
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
