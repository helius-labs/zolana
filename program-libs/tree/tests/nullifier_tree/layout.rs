use zolana_tree::nullifier_tree::{
    batch::{Batch, BatchState, CachedTreeUpdate},
    error::NullifierTreeError,
    layout::{NullifierTreeLayout, RootHistory},
};

fn new_queue<const ZKP: usize>(
    batch_size: u64,
    zkp_batch_size: u64,
    start_index: u64,
) -> Result<NullifierTreeLayout<ZKP>, NullifierTreeError> {
    NullifierTreeLayout::<ZKP>::new_queue_validated(batch_size, zkp_batch_size, start_index)
}

#[test]
fn tree_layout_round_trips() {
    let mut bytes = vec![0u8; core::mem::size_of::<NullifierTreeLayout<2>>()];
    let layout: &mut NullifierTreeLayout<2> = wincode::deserialize_mut(&mut bytes).unwrap();
    layout.root_history.roots[1] = [7u8; 32];
    layout.batches[0].set_hash_chain(1, [9u8; 32]);
    let cached = CachedTreeUpdate {
        old_root: [3u8; 32],
        new_root: [4u8; 32],
        occupied: 1,
    };
    layout.batches[1].set_cached_tree_update(1, cached);
    let reloaded: &mut NullifierTreeLayout<2> = wincode::deserialize_mut(&mut bytes).unwrap();
    assert_eq!(reloaded.root_history.roots[1], [7u8; 32]);
    assert_eq!(reloaded.batches[0].hash_chain(1), Some([9u8; 32]));
    assert_eq!(reloaded.batches[1].cached_tree_update(1), Some(cached));
}

#[test]
fn test_increment_next_pending_batch_index_if_inserted() {
    let mut metadata = new_queue::<1>(10, 10, 0).unwrap();
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
    let mut metadata = new_queue::<1>(10, 10, 0).unwrap();
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
        NullifierTreeLayout::<5>::validate_configuration(10, 3),
        Err(NullifierTreeError::BatchSizeNotDivisibleByZkpBatchSize)
    );
    assert_eq!(
        NullifierTreeLayout::<5>::validate_configuration(10, 2),
        Ok(())
    );
    assert_eq!(
        NullifierTreeLayout::<4>::validate_configuration(10, 2),
        Err(NullifierTreeError::InvalidRootHistoryCapacity)
    );
}

#[test]
fn test_new_initializes_entire_queue() {
    let metadata = new_queue::<5>(10, 2, 7).unwrap();
    assert_eq!(
        metadata,
        NullifierTreeLayout {
            tree_type: 0,
            sequence_number: 0,
            next_index: 0,
            height: 0,
            currently_processing_batch_index: 0,
            capacity: 0,
            batch_size: 10,
            zkp_batch_size: 2,
            pending_batch_index: 0,
            queue_next_index: 0,
            close_before_index: 0,
            root_history: RootHistory {
                current_index: 0,
                roots: [[0u8; 32]; 5],
            },
            batches: [Batch::new(10, 2, 7), Batch::new(10, 2, 17)],
        }
    );
    assert_eq!(
        new_queue::<5>(10, 2, u64::MAX),
        Err(NullifierTreeError::ArithmeticOverflow)
    );
}

#[test]
fn test_get_num_zkp_batches() {
    let metadata = new_queue::<5>(10, 2, 0).unwrap();
    assert_eq!(metadata.get_num_zkp_batches(), 5);
}

#[test]
fn test_get_current_batch() {
    let mut metadata = new_queue::<5>(10, 2, 0).unwrap();
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
