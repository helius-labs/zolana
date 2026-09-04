use zolana_hasher::{Hasher, Poseidon};
use zolana_tree::nullifier_tree::{
    batch::{Batch, BatchState},
    error::NullifierTreeError,
};

/// 500 / 100 = 5 ZKP batches, so the batch carries five hash chains.
fn get_test_batch() -> Batch<5> {
    Batch::new(500, 100, 0)
}

/// simulate zkp batch insertion
fn test_mark_as_inserted(mut batch: Batch<5>) {
    // Neither insertion nor reuse touches the hash chains, so every reference
    // batch below carries the ones the batch came in with.
    let hash_chains: Vec<[u8; 32]> = (0..batch.get_num_zkp_batches() as usize)
        .map(|index| batch.hash_chain(index).unwrap())
        .collect();
    let reference_batch = || {
        let mut reference = get_test_batch();
        for (index, hash_chain) in hash_chains.iter().enumerate() {
            reference.set_hash_chain(index, *hash_chain);
        }
        reference
    };

    for i in 0..batch.get_num_zkp_batches() {
        batch.mark_as_inserted_in_merkle_tree().unwrap();
        if i != batch.get_num_zkp_batches() - 1 {
            assert_eq!(batch.get_state(), BatchState::Full);
            assert_eq!(batch.num_inserted(), 0);
            assert_eq!(batch.get_current_zkp_batch_index(), 5);
            assert_eq!(batch.get_num_inserted_zkps(), i + 1);
        } else {
            assert_eq!(batch.get_state(), BatchState::Inserted);
            assert_eq!(batch.num_inserted(), 0);
            assert_eq!(batch.get_current_zkp_batch_index(), 5);
            assert_eq!(batch.get_num_inserted_zkps(), i + 1);
        }
    }
    assert_eq!(batch.get_state(), BatchState::Inserted);
    assert_eq!(batch.num_inserted(), 0);
    let mut ref_batch = reference_batch();
    ref_batch.set_state(BatchState::Inserted);
    ref_batch.set_num_inserted_zkp_batches(5);
    ref_batch.set_num_full_zkp_batches(5);
    assert_eq!(batch, ref_batch);
    batch.advance_state_to_fill(1).unwrap();
    let mut ref_batch = reference_batch();
    ref_batch.start_index = 1;
    assert_eq!(batch, ref_batch);
}

#[test]
fn test_insert() {
    let mut batch = get_test_batch();
    let mut ref_batch = get_test_batch();
    for i in 0..batch.batch_size {
        ref_batch.set_num_inserted(ref_batch.num_inserted() % ref_batch.zkp_batch_size);

        let chain_index = batch.num_full_zkp_batches() as usize;
        let mut value = [0u8; 32];
        value[24..].copy_from_slice(&i.to_be_bytes());
        #[allow(clippy::manual_is_multiple_of)]
        let ref_hash_chain = if i % batch.zkp_batch_size == 0 {
            value
        } else {
            Poseidon::hashv(&[&batch.hash_chain(chain_index).unwrap(), &value]).unwrap()
        };
        let result = batch.add_to_hash_chain(&value);
        assert!(result.is_ok(), "Failed result: {:?}", result);
        ref_batch.set_hash_chain(chain_index, ref_hash_chain);

        ref_batch.set_num_inserted(ref_batch.num_inserted() + 1);
        if ref_batch.num_inserted() == ref_batch.zkp_batch_size {
            ref_batch.set_num_full_zkp_batches(ref_batch.num_full_zkp_batches() + 1);
            ref_batch.set_num_inserted(0);
        }
        if i == batch.batch_size - 1 {
            ref_batch.set_state(BatchState::Full);
            ref_batch.set_num_inserted(0);
        }
        assert_eq!(batch, ref_batch);
    }
    test_mark_as_inserted(batch);
}

#[test]
fn test_add_to_hash_chain() {
    let mut batch = get_test_batch();
    let value = [1u8; 32];

    assert!(batch.add_to_hash_chain(&value).is_ok());
    let mut ref_batch = get_test_batch();
    let user_hash_chain = value;
    ref_batch.set_num_inserted(1);
    ref_batch.set_hash_chain(0, user_hash_chain);
    assert_eq!(batch, ref_batch);
    let value = [2u8; 32];
    let ref_hash_chain = Poseidon::hashv(&[&user_hash_chain, &value]).unwrap();
    assert!(batch.add_to_hash_chain(&value).is_ok());

    ref_batch.set_num_inserted(2);
    ref_batch.set_hash_chain(0, ref_hash_chain);
    assert_eq!(batch, ref_batch);
}

/// A failed insert must not mutate the batch, hash chains included: host
/// callers keep the state after an error.
#[test]
fn test_add_to_hash_chain_is_error_atomic() {
    let mut batch = get_test_batch();
    batch.advance_state_to_full().unwrap();
    let batch_before = batch;
    assert_eq!(
        batch.add_to_hash_chain(&[9u8; 32]).unwrap_err(),
        NullifierTreeError::BatchNotReady
    );
    assert_eq!(batch, batch_before);
}

#[test]
fn test_getters() {
    let mut batch = get_test_batch();
    assert_eq!(batch.get_num_zkp_batches(), 5);
    assert_eq!(batch.get_state(), BatchState::Fill);
    assert_eq!(batch.num_inserted(), 0);
    assert_eq!(batch.get_current_zkp_batch_index(), 0);
    assert_eq!(batch.get_num_inserted_zkps(), 0);
    batch.advance_state_to_full().unwrap();
    assert_eq!(batch.get_state(), BatchState::Full);
    batch.advance_state_to_inserted().unwrap();
    assert_eq!(batch.get_state(), BatchState::Inserted);
}

/// 1. Failing: empty batch
/// 2. Functional: if zkp batch size is full else failing
/// 3. Failing: batch is completely inserted
#[test]
fn test_can_insert_batch() {
    let mut batch = get_test_batch();
    assert_eq!(
        batch.get_first_ready_zkp_batch(),
        Err(NullifierTreeError::BatchNotReady)
    );
    for i in 0..batch.batch_size + 10 {
        let mut value = [0u8; 32];
        value[24..].copy_from_slice(&i.to_be_bytes());
        if i < batch.batch_size {
            batch.add_to_hash_chain(&value).unwrap();
        }
        #[allow(clippy::manual_is_multiple_of)]
        if (i + 1) % batch.zkp_batch_size == 0 && i != 0 {
            assert_eq!(
                batch.get_first_ready_zkp_batch().unwrap(),
                i / batch.zkp_batch_size
            );
            batch.mark_as_inserted_in_merkle_tree().unwrap();
        } else if i >= batch.batch_size {
            assert_eq!(
                batch.get_first_ready_zkp_batch(),
                Err(NullifierTreeError::BatchAlreadyInserted)
            );
        } else {
            assert_eq!(
                batch.get_first_ready_zkp_batch(),
                Err(NullifierTreeError::BatchNotReady)
            );
        }
    }
}

#[test]
fn test_get_state() {
    let mut batch = get_test_batch();
    assert_eq!(batch.get_state(), BatchState::Fill);
    {
        let result = batch.advance_state_to_inserted();
        assert_eq!(result, Err(NullifierTreeError::BatchNotReady));
        let result = batch.advance_state_to_fill(0);
        assert_eq!(result, Err(NullifierTreeError::BatchNotReady));
    }
    batch.advance_state_to_full().unwrap();
    assert_eq!(batch.get_state(), BatchState::Full);
    {
        let result = batch.advance_state_to_full();
        assert_eq!(result, Err(NullifierTreeError::BatchNotReady));
        let result = batch.advance_state_to_fill(0);
        assert_eq!(result, Err(NullifierTreeError::BatchNotReady));
    }
    batch.advance_state_to_inserted().unwrap();
    assert_eq!(batch.get_state(), BatchState::Inserted);
}

#[test]
fn advance_state_to_fill_resets_num_inserted() {
    let mut batch = get_test_batch();
    batch.set_num_inserted(42);
    batch.set_state(BatchState::Inserted);
    batch.advance_state_to_fill(123).unwrap();
    assert_eq!(batch.start_index, 123);
    assert_eq!(batch.num_inserted(), 0);
    assert_eq!(batch.get_num_inserted_elements(), 0);
}

/// Account-data paths must return `InvalidBatchState` for a corrupt state
/// word instead of panicking in `From<u64>`.
#[test]
fn corrupt_state_errors_instead_of_panicking() {
    let mut batch = get_test_batch();
    batch.set_raw_state(3);
    assert_eq!(
        batch.advance_state_to_full().unwrap_err(),
        NullifierTreeError::InvalidBatchState
    );
    assert_eq!(
        batch.advance_state_to_inserted().unwrap_err(),
        NullifierTreeError::InvalidBatchState
    );
    assert_eq!(
        batch.advance_state_to_fill(0).unwrap_err(),
        NullifierTreeError::InvalidBatchState
    );
    assert_eq!(
        batch.get_first_ready_zkp_batch().unwrap_err(),
        NullifierTreeError::InvalidBatchState
    );
    assert_eq!(
        batch.add_to_hash_chain(&[1u8; 32]).unwrap_err(),
        NullifierTreeError::InvalidBatchState
    );
    assert_eq!(
        batch.mark_as_inserted_in_merkle_tree().unwrap_err(),
        NullifierTreeError::InvalidBatchState
    );
}

#[test]
fn try_get_state_maps_known_states_and_returns_none_for_invalid() {
    let mut batch = get_test_batch();
    for (raw, state) in [
        (0, BatchState::Fill),
        (1, BatchState::Inserted),
        (2, BatchState::Full),
    ] {
        batch.set_raw_state(raw);
        assert_eq!(batch.try_get_state(), Some(state));
    }

    batch.set_raw_state(3);
    assert_eq!(batch.try_get_state(), None);
}

#[test]
fn test_num_ready_zkp_updates() {
    let mut batch = get_test_batch();
    assert_eq!(batch.get_num_ready_zkp_updates(), 0);
    batch.set_num_full_zkp_batches(1);
    assert_eq!(batch.get_num_ready_zkp_updates(), 1);
    batch.set_num_inserted_zkp_batches(1);
    assert_eq!(batch.get_num_ready_zkp_updates(), 0);
    batch.set_num_full_zkp_batches(2);
    assert_eq!(batch.get_num_ready_zkp_updates(), 1);
}

#[test]
fn test_get_num_inserted_elements() {
    let mut batch = get_test_batch();
    assert_eq!(batch.get_num_inserted_elements(), 0);

    for i in 0..batch.batch_size {
        let mut value = [0u8; 32];
        value[24..].copy_from_slice(&i.to_be_bytes());
        batch.add_to_hash_chain(&value).unwrap();
        assert_eq!(batch.get_num_inserted_elements(), i + 1);
    }
}
