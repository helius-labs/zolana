use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::{
    batch::{Batch, BatchState},
    constants::NUM_BATCHES,
    errors::{BatchedMerkleTreeError, MerkleTreeMetadataError},
    BorshDeserialize, BorshSerialize,
};

#[repr(C)]
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Debug,
    PartialEq,
    Default,
    Clone,
    Copy,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    bytemuck::Pod,
    bytemuck::Zeroable,
)]
pub struct QueueBatches {
    /// Reserved account-layout field. Must contain [`NUM_BATCHES`] on load.
    pub reserved: u64,
    /// Number of elements in a batch.
    pub batch_size: u64,
    /// Number of elements in a ZKP batch.
    /// A batch has one or more ZKP batches.
    pub zkp_batch_size: u64,
    /// Batch elements are currently inserted in.
    pub currently_processing_batch_index: u64,
    /// Next batch to be inserted into the tree.
    pub pending_batch_index: u64,
    /// Output queues require next index to derive compressed account hashes.
    /// Output & Address queues append state hence need to check tree capacity.
    /// next_index in queue is ahead or equal to next index in the associated
    /// batched Merkle tree account.
    pub next_index: u64,
    pub batches: [Batch; 2],
}

impl QueueBatches {
    /// Returns the number of ZKP batches contained within a single regular batch.
    pub fn get_num_zkp_batches(&self) -> u64 {
        self.batch_size / self.zkp_batch_size
    }

    pub fn rotation(&self) -> Result<u64, BatchedMerkleTreeError> {
        (NUM_BATCHES as u64)
            .checked_mul(self.batch_size)
            .ok_or(BatchedMerkleTreeError::ArithmeticOverflow)
    }

    pub fn get_current_batch(&self) -> Result<&Batch, BatchedMerkleTreeError> {
        self.batches
            .get(self.currently_processing_batch_index as usize)
            .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)
    }

    pub fn get_current_batch_mut(&mut self) -> Result<&mut Batch, BatchedMerkleTreeError> {
        self.batches
            .get_mut(self.currently_processing_batch_index as usize)
            .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)
    }

    /// Validates the queue, root-history, and cached-update capacities together.
    /// A root is appended for each ZKP batch, so one queue batch must contain
    /// exactly as many ZKP batches as both fixed-size account regions can hold.
    pub fn validate_configuration<const RH: usize, const ZKP: usize>(
        batch_size: u64,
        zkp_batch_size: u64,
    ) -> Result<u32, BatchedMerkleTreeError> {
        if batch_size == 0 || zkp_batch_size == 0 || !batch_size.is_multiple_of(zkp_batch_size) {
            return Err(BatchedMerkleTreeError::BatchSizeNotDivisibleByZkpBatchSize);
        }

        let zkp_batches = batch_size / zkp_batch_size;
        let root_history_capacity = u32::try_from(zkp_batches)
            .map_err(|_| MerkleTreeMetadataError::InvalidRootHistoryCapacity)?;
        if RH != ZKP || zkp_batches != RH as u64 {
            return Err(MerkleTreeMetadataError::InvalidRootHistoryCapacity.into());
        }
        Ok(root_history_capacity)
    }

    /// Initializes all queue metadata and both batches from an already
    /// validated configuration.
    pub(crate) fn new(
        batch_size: u64,
        zkp_batch_size: u64,
        start_index: u64,
    ) -> Result<Self, BatchedMerkleTreeError> {
        let second_batch_start_index = start_index
            .checked_add(batch_size)
            .ok_or(BatchedMerkleTreeError::ArithmeticOverflow)?;

        Ok(QueueBatches {
            reserved: NUM_BATCHES as u64,
            zkp_batch_size,
            batch_size,
            currently_processing_batch_index: 0,
            pending_batch_index: 0,
            next_index: 0,
            batches: [
                Batch::new(batch_size, zkp_batch_size, start_index),
                Batch::new(batch_size, zkp_batch_size, second_batch_start_index),
            ],
        })
    }

    /// Increment the next full batch index if current state is BatchState::Inserted.
    pub fn increment_pending_batch_index_if_inserted(&mut self, state: BatchState) {
        if state == BatchState::Inserted {
            self.pending_batch_index = (self.pending_batch_index + 1) % NUM_BATCHES as u64;
        }
    }

    /// Increment the currently_processing_batch_index if current state is BatchState::Full.
    pub fn increment_currently_processing_batch_index_if_full(
        &mut self,
    ) -> Result<(), BatchedMerkleTreeError> {
        let state = self.get_current_batch()?.checked_state()?;
        if state == BatchState::Full {
            self.currently_processing_batch_index =
                (self.currently_processing_batch_index + 1) % NUM_BATCHES as u64;
        }
        Ok(())
    }
}

#[cfg(test)]
fn new_queue<const RH: usize, const ZKP: usize>(
    batch_size: u64,
    zkp_batch_size: u64,
    start_index: u64,
) -> Result<QueueBatches, BatchedMerkleTreeError> {
    QueueBatches::validate_configuration::<RH, ZKP>(batch_size, zkp_batch_size)?;
    QueueBatches::new(batch_size, zkp_batch_size, start_index)
}

#[test]
fn test_increment_next_pending_batch_index_if_inserted() {
    let mut metadata = new_queue::<1, 1>(10, 10, 0).unwrap();
    assert_eq!(metadata.pending_batch_index, 0);
    // increment next full batch index
    metadata.increment_pending_batch_index_if_inserted(BatchState::Inserted);
    assert_eq!(metadata.pending_batch_index, 1);
    // increment next full batch index
    metadata.increment_pending_batch_index_if_inserted(BatchState::Inserted);
    assert_eq!(metadata.pending_batch_index, 0);
    // try incrementing next full batch index with state not inserted
    metadata.increment_pending_batch_index_if_inserted(BatchState::Fill);
    assert_eq!(metadata.pending_batch_index, 0);
    metadata.increment_pending_batch_index_if_inserted(BatchState::Full);
    assert_eq!(metadata.pending_batch_index, 0);
}

#[test]
fn test_increment_currently_processing_batch_index_if_full() {
    let mut metadata = new_queue::<1, 1>(10, 10, 0).unwrap();
    assert_eq!(metadata.currently_processing_batch_index, 0);
    metadata
        .get_current_batch_mut()
        .unwrap()
        .advance_state_to_full()
        .unwrap();
    // increment currently_processing_batch_index
    metadata
        .increment_currently_processing_batch_index_if_full()
        .unwrap();
    assert_eq!(metadata.currently_processing_batch_index, 1);
    assert_eq!(metadata.pending_batch_index, 0);
    metadata
        .get_current_batch_mut()
        .unwrap()
        .advance_state_to_full()
        .unwrap();
    // increment currently_processing_batch_index
    metadata
        .increment_currently_processing_batch_index_if_full()
        .unwrap();
    assert_eq!(metadata.currently_processing_batch_index, 0);
    metadata
        .get_current_batch_mut()
        .unwrap()
        .advance_state_to_inserted()
        .unwrap();
    // try incrementing next full batch index with state not full
    metadata
        .increment_currently_processing_batch_index_if_full()
        .unwrap();
    assert_eq!(metadata.currently_processing_batch_index, 0);
    metadata
        .get_current_batch_mut()
        .unwrap()
        .advance_state_to_fill(0)
        .unwrap();
    metadata
        .increment_currently_processing_batch_index_if_full()
        .unwrap();
    assert_eq!(metadata.currently_processing_batch_index, 0);
}

#[test]
fn test_validate_batch_sizes() {
    assert_eq!(
        QueueBatches::validate_configuration::<5, 5>(10, 3),
        Err(BatchedMerkleTreeError::BatchSizeNotDivisibleByZkpBatchSize)
    );
    assert_eq!(QueueBatches::validate_configuration::<5, 5>(10, 2), Ok(5));
    assert_eq!(
        QueueBatches::validate_configuration::<4, 4>(10, 2),
        Err(MerkleTreeMetadataError::InvalidRootHistoryCapacity.into())
    );
    assert_eq!(
        QueueBatches::validate_configuration::<5, 4>(10, 2),
        Err(MerkleTreeMetadataError::InvalidRootHistoryCapacity.into())
    );
}

#[test]
fn test_new_initializes_entire_queue() {
    let metadata = new_queue::<5, 5>(10, 2, 7).unwrap();
    assert_eq!(
        metadata,
        QueueBatches {
            reserved: NUM_BATCHES as u64,
            batch_size: 10,
            zkp_batch_size: 2,
            currently_processing_batch_index: 0,
            pending_batch_index: 0,
            next_index: 0,
            batches: [Batch::new(10, 2, 7), Batch::new(10, 2, 17)],
        }
    );
    assert_eq!(
        QueueBatches::new(10, 2, u64::MAX),
        Err(BatchedMerkleTreeError::ArithmeticOverflow)
    );
}

#[test]
fn test_get_num_zkp_batches() {
    let metadata = new_queue::<5, 5>(10, 2, 0).unwrap();
    assert_eq!(metadata.get_num_zkp_batches(), 5);
}

#[test]
fn test_get_current_batch() {
    let mut metadata = new_queue::<5, 5>(10, 2, 0).unwrap();
    assert_eq!(
        metadata.get_current_batch().unwrap().get_state(),
        BatchState::Fill
    );
    metadata
        .get_current_batch_mut()
        .unwrap()
        .advance_state_to_full()
        .unwrap();
    assert_eq!(
        metadata.get_current_batch().unwrap().get_state(),
        BatchState::Full
    );
    metadata
        .get_current_batch_mut()
        .unwrap()
        .advance_state_to_inserted()
        .unwrap();
    assert_eq!(
        metadata.get_current_batch().unwrap().get_state(),
        BatchState::Inserted
    );
}
