use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::{
    batch::{Batch, BatchState},
    constants::NUM_BATCHES,
    errors::BatchedMerkleTreeError,
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
    /// Number of batches.
    pub num_batches: u64,
    /// Number of elements in a batch.
    pub batch_size: u64,
    /// Number of elements in a ZKP batch.
    /// A batch has one or more ZKP batches.
    pub zkp_batch_size: u64,
    /// Bloom filter capacity in bits. Matches upstream's `bloom_filter_capacity`
    /// at the same struct offset. Set at init from the `BLOOM` byte size so that
    /// indexers parsing our account with the upstream crate size the bloom
    /// region correctly (`bloom_filter_capacity / 8` bytes).
    pub bloom_filter_capacity: u64,
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

    pub fn get_current_batch(&self) -> Result<&Batch, BatchedMerkleTreeError> {
        self.batches
            .get(self.currently_processing_batch_index as usize)
            .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)
    }

    pub fn get_current_batch_index(&self) -> usize {
        self.currently_processing_batch_index as usize
    }

    pub fn get_previous_batch_index(&self) -> usize {
        if self.currently_processing_batch_index == 0 {
            1
        } else {
            0
        }
    }

    pub fn get_previous_batch(&self) -> Result<&Batch, BatchedMerkleTreeError> {
        self.batches
            .get(self.get_previous_batch_index())
            .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)
    }

    pub fn get_previous_batch_mut(&mut self) -> Result<&mut Batch, BatchedMerkleTreeError> {
        let index = self.get_previous_batch_index();
        self.batches
            .get_mut(index)
            .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)
    }

    pub fn get_current_batch_mut(&mut self) -> Result<&mut Batch, BatchedMerkleTreeError> {
        self.batches
            .get_mut(self.currently_processing_batch_index as usize)
            .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)
    }

    /// Validates that the batch size is properly divisible by the ZKP batch size.
    fn check_batch_size_divisible_by_zkp_batch_size(
        batch_size: u64,
        zkp_batch_size: u64,
    ) -> Result<(), BatchedMerkleTreeError> {
        #[allow(clippy::manual_is_multiple_of)]
        if batch_size % zkp_batch_size != 0 {
            return Err(BatchedMerkleTreeError::BatchSizeNotDivisibleByZkpBatchSize);
        }
        Ok(())
    }

    pub fn new_output_queue(
        batch_size: u64,
        zkp_batch_size: u64,
    ) -> Result<Self, BatchedMerkleTreeError> {
        Self::check_batch_size_divisible_by_zkp_batch_size(batch_size, zkp_batch_size)?;
        Ok(QueueBatches {
            num_batches: NUM_BATCHES as u64,
            zkp_batch_size,
            bloom_filter_capacity: 0,
            batch_size,
            currently_processing_batch_index: 0,
            pending_batch_index: 0,
            next_index: 0,
            batches: [
                Batch::new(batch_size, zkp_batch_size, 0),
                Batch::new(batch_size, zkp_batch_size, batch_size),
            ],
        })
    }

    pub fn new_input_queue(
        batch_size: u64,
        zkp_batch_size: u64,
        start_index: u64,
    ) -> Result<Self, BatchedMerkleTreeError> {
        Self::check_batch_size_divisible_by_zkp_batch_size(batch_size, zkp_batch_size)?;

        Ok(QueueBatches {
            num_batches: NUM_BATCHES as u64,
            zkp_batch_size,
            bloom_filter_capacity: 0,
            batch_size,
            currently_processing_batch_index: 0,
            pending_batch_index: 0,
            next_index: 0,
            batches: [
                Batch::new(batch_size, zkp_batch_size, start_index),
                Batch::new(batch_size, zkp_batch_size, batch_size + start_index),
            ],
        })
    }

    /// Increment the next full batch index if current state is BatchState::Inserted.
    pub fn increment_pending_batch_index_if_inserted(&mut self, state: BatchState) {
        if state == BatchState::Inserted {
            self.pending_batch_index = (self.pending_batch_index + 1) % self.num_batches;
        }
    }

    /// Increment the currently_processing_batch_index if current state is BatchState::Full.
    pub fn increment_currently_processing_batch_index_if_full(
        &mut self,
    ) -> Result<(), BatchedMerkleTreeError> {
        let state = self.get_current_batch()?.get_state();
        if state == BatchState::Full {
            self.currently_processing_batch_index =
                (self.currently_processing_batch_index + 1) % self.num_batches;
        }
        Ok(())
    }

    pub fn init(
        &mut self,
        batch_size: u64,
        zkp_batch_size: u64,
    ) -> Result<(), BatchedMerkleTreeError> {
        Self::check_batch_size_divisible_by_zkp_batch_size(batch_size, zkp_batch_size)?;
        self.num_batches = NUM_BATCHES as u64;
        self.batch_size = batch_size;
        self.zkp_batch_size = zkp_batch_size;
        Ok(())
    }
}

#[test]
fn test_increment_next_pending_batch_index_if_inserted() {
    let mut metadata = QueueBatches::new_input_queue(10, 10, 0).unwrap();
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
    let mut metadata = QueueBatches::new_input_queue(10, 10, 0).unwrap();
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
        .advance_state_to_fill(None)
        .unwrap();
    metadata
        .increment_currently_processing_batch_index_if_full()
        .unwrap();
    assert_eq!(metadata.currently_processing_batch_index, 0);
}

#[test]
fn test_validate_batch_sizes() {
    assert!(QueueBatches::check_batch_size_divisible_by_zkp_batch_size(10, 3).is_err());
    assert!(QueueBatches::check_batch_size_divisible_by_zkp_batch_size(10, 2).is_ok());
}

#[test]
fn test_batch_size_validation() {
    // Test invalid batch size
    assert!(QueueBatches::new_input_queue(10, 3, 0).is_err());
    assert!(QueueBatches::new_output_queue(10, 3).is_err());

    // Test valid batch size
    assert!(QueueBatches::new_input_queue(9, 3, 0).is_ok());
    assert!(QueueBatches::new_output_queue(9, 3).is_ok());
}

#[test]
fn test_init() {
    let mut metadata = QueueBatches::new_output_queue(10, 2).unwrap();
    assert!(metadata.init(12, 5).is_err());
    assert!(metadata.init(10, 2).is_ok());
    assert_eq!(metadata.batch_size, 10);
    assert_eq!(metadata.zkp_batch_size, 2);
}

#[test]
fn test_get_num_zkp_batches() {
    let metadata = QueueBatches::new_output_queue(10, 2).unwrap();
    assert_eq!(metadata.get_num_zkp_batches(), 5);
}

#[test]
fn test_get_current_batch() {
    let mut metadata = QueueBatches::new_output_queue(10, 2).unwrap();
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

#[test]
fn test_get_current_batch_index_and_batch() {
    let mut metadata = QueueBatches::new_output_queue(10, 2).unwrap();
    {
        let previous_batch_index = metadata.get_previous_batch_index();
        assert_eq!(previous_batch_index, 1);
        let previous_batch = metadata.get_previous_batch().unwrap();
        assert_eq!(previous_batch.start_index, 10);
        let previous_batch = metadata.get_previous_batch_mut().unwrap();
        assert_eq!(previous_batch.start_index, 10);
    }

    {
        metadata.currently_processing_batch_index = 1;
        assert_eq!(metadata.get_previous_batch_index(), 0);
        let previous_batch = metadata.get_previous_batch().unwrap();
        assert_eq!(previous_batch.start_index, 0);
        let previous_batch = metadata.get_previous_batch_mut().unwrap();
        assert_eq!(previous_batch.start_index, 0);
    }
    {
        metadata.currently_processing_batch_index = 0;
        let previous_batch = metadata.get_previous_batch().unwrap();
        assert_eq!(previous_batch.start_index, 10);
        let previous_batch = metadata.get_previous_batch_mut().unwrap();
        assert_eq!(previous_batch.start_index, 10);
    }
    {
        metadata.currently_processing_batch_index = 1;
        assert_eq!(metadata.get_previous_batch_index(), 0);
        let previous_batch = metadata.get_previous_batch().unwrap();
        assert_eq!(previous_batch.start_index, 0);
        let previous_batch = metadata.get_previous_batch_mut().unwrap();
        assert_eq!(previous_batch.start_index, 0);
    }
}
