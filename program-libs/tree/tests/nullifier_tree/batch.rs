use zolana_hasher::{hash_chain::create_hash_chain_4_from_slice, Hasher, Poseidon};
use zolana_tree::nullifier_tree::{
    batch::{Batch, BatchState},
    error::NullifierTreeError,
    init::{hash_chain_groups_are_full, SUPPORTED_ZKP_BATCH_SIZES},
};

/// 500 / 100 = 5 ZKP batches, so the batch carries five hash chains.
fn get_test_batch() -> Batch<5> {
    Batch::new(500, 100, 0)
}

fn value_from(i: u64) -> [u8; 32] {
    let mut value = [0u8; 32];
    value[24..].copy_from_slice(&i.to_be_bytes());
    value
}

/// simulate zkp batch insertion
fn test_mark_as_inserted(mut batch: Batch<5>) {
    // Neither insertion nor reuse touches the hash chains or the pending
    // values, so every reference batch below carries the ones the batch came
    // in with.
    let hash_chains: Vec<[u8; 32]> = (0..batch.get_num_zkp_batches() as usize)
        .map(|index| batch.hash_chain(index).unwrap())
        .collect();
    let pending_values = *batch.pending_values();
    let reference_batch = || {
        let mut reference = get_test_batch();
        for (index, hash_chain) in hash_chains.iter().enumerate() {
            reference.set_hash_chain(index, *hash_chain);
        }
        for (slot, value) in pending_values.iter().enumerate() {
            reference.set_pending_value(slot, *value);
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

/// The reference mirrors every write the batch makes: a value that is
/// absorbed rewrites the chain as `hash_chain_4` over the open zkp batch so
/// far, a value that waits is written to its pending slot, and stale pending
/// slots are left alone on both sides.
#[test]
fn test_insert() {
    let mut batch = get_test_batch();
    let mut ref_batch = get_test_batch();
    let mut open_zkp_batch: Vec<[u8; 32]> = Vec::new();
    for i in 0..batch.batch_size {
        let chain_index = batch.num_full_zkp_batches() as usize;
        let value = value_from(i);
        let num_pending = batch.num_pending();
        open_zkp_batch.push(value);
        let completes_zkp_batch = open_zkp_batch.len() as u64 == batch.zkp_batch_size;
        let absorbs = open_zkp_batch.len() == 1 || num_pending == 2 || completes_zkp_batch;

        let result = batch.add_to_hash_chain(&value);
        assert!(result.is_ok(), "Failed result: {:?}", result);

        if absorbs {
            ref_batch.set_hash_chain(
                chain_index,
                create_hash_chain_4_from_slice(&open_zkp_batch).unwrap(),
            );
        } else {
            ref_batch.set_pending_value(num_pending, value);
        }
        ref_batch.set_num_inserted(open_zkp_batch.len() as u64);
        if completes_zkp_batch {
            ref_batch.set_num_full_zkp_batches(ref_batch.num_full_zkp_batches() + 1);
            ref_batch.set_num_inserted(0);
            open_zkp_batch.clear();
        }
        if i == batch.batch_size - 1 {
            ref_batch.set_state(BatchState::Full);
        }
        assert_eq!(batch, ref_batch);
    }
    test_mark_as_inserted(batch);
}

/// The head is written at once; the next two values wait in the pending
/// buffer without touching the chain; the fourth absorbs all three in one
/// 4-input Poseidon call.
#[test]
fn test_add_to_hash_chain() {
    let mut batch = get_test_batch();
    let mut ref_batch = get_test_batch();
    let values = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    let [head, second, third, fourth] = values;

    batch.add_to_hash_chain(&head).unwrap();
    ref_batch.set_num_inserted(1);
    ref_batch.set_hash_chain(0, head);
    assert_eq!(batch, ref_batch);
    assert_eq!(batch.num_pending(), 0);

    batch.add_to_hash_chain(&second).unwrap();
    ref_batch.set_num_inserted(2);
    ref_batch.set_pending_value(0, second);
    assert_eq!(batch, ref_batch);
    assert_eq!(batch.num_pending(), 1);
    assert_eq!(batch.hash_chain(0), Some(head));

    batch.add_to_hash_chain(&third).unwrap();
    ref_batch.set_num_inserted(3);
    ref_batch.set_pending_value(1, third);
    assert_eq!(batch, ref_batch);
    assert_eq!(batch.num_pending(), 2);
    assert_eq!(batch.hash_chain(0), Some(head));

    batch.add_to_hash_chain(&fourth).unwrap();
    ref_batch.set_num_inserted(4);
    ref_batch.set_hash_chain(
        0,
        Poseidon::hashv(&[&head, &second, &third, &fourth]).unwrap(),
    );
    assert_eq!(batch, ref_batch);
    assert_eq!(batch.num_pending(), 0);
    assert_eq!(
        batch.hash_chain(0),
        Some(create_hash_chain_4_from_slice(&values).unwrap())
    );
}

/// A zkp batch whose size is not `1 + 3k` ends with a partial group; the
/// finalized chain must equal the slice fold, which zero-pads that group.
#[test]
fn finalized_chain_equals_hash_chain_4_for_every_group_remainder() {
    for zkp_batch_size in [1u64, 2, 3, 4, 5, 6, 7] {
        let mut batch: Batch<2> = Batch::new(2 * zkp_batch_size, zkp_batch_size, 0);
        let values: Vec<[u8; 32]> = (1..=zkp_batch_size).map(value_from).collect();
        for value in &values {
            batch.add_to_hash_chain(value).unwrap();
        }
        assert_eq!(batch.num_full_zkp_batches(), 1);
        assert_eq!(batch.num_pending(), 0);
        assert_eq!(
            batch.hash_chain(0),
            Some(create_hash_chain_4_from_slice(&values).unwrap()),
            "zkp batch size {zkp_batch_size}"
        );
    }
}

/// Spelled-out expectation for one padded shape, independent of the hasher's
/// own fold: five values are `Poseidon(Poseidon(v1, v2, v3, v4), v5, 0, 0)`.
#[test]
fn finalized_chain_of_five_pads_the_last_group_with_zeros() {
    let mut batch: Batch<2> = Batch::new(10, 5, 0);
    let values: Vec<[u8; 32]> = (1..=5).map(value_from).collect();
    for value in &values {
        batch.add_to_hash_chain(value).unwrap();
    }
    let [v1, v2, v3, v4, v5] = values.as_slice() else {
        panic!("five values");
    };
    let first_group = Poseidon::hashv(&[v1, v2, v3, v4]).unwrap();
    let zero = [0u8; 32];
    let expected = Poseidon::hashv(&[&first_group, v5, &zero, &zero]).unwrap();
    assert_eq!(batch.hash_chain(0), Some(expected));
}

/// Padding is reachable for an arbitrary zkp batch size, but not for one a
/// tree can be created with: every supported size leaves two values pending
/// before its last insert, so that insert absorbs a full group and no chain a
/// real tree builds is ever zero-padded. `SUPPORTED_ZKP_BATCH_SIZES` is held
/// to this at compile time; this is the same claim through the insertion path.
#[test]
fn supported_zkp_batch_sizes_never_pad_the_hash_chain() {
    for zkp_batch_size in SUPPORTED_ZKP_BATCH_SIZES {
        assert!(
            hash_chain_groups_are_full(zkp_batch_size),
            "zkp batch size {zkp_batch_size}"
        );

        let mut batch: Batch<2> = Batch::new(2 * zkp_batch_size, zkp_batch_size, 0);
        let values: Vec<[u8; 32]> = (1..=zkp_batch_size).map(value_from).collect();
        let (last, rest) = values.split_last().expect("a supported size is non-zero");
        for value in rest {
            batch.add_to_hash_chain(value).unwrap();
        }
        assert_eq!(batch.num_pending(), 2, "zkp batch size {zkp_batch_size}");

        batch.add_to_hash_chain(last).unwrap();
        assert_eq!(batch.num_full_zkp_batches(), 1);
        assert_eq!(
            batch.hash_chain(0),
            Some(create_hash_chain_4_from_slice(&values).unwrap()),
            "zkp batch size {zkp_batch_size}"
        );
    }
}

#[test]
fn num_pending_follows_num_inserted() {
    let mut batch = get_test_batch();
    assert_eq!(batch.num_pending(), 0);
    for i in 0..batch.zkp_batch_size {
        batch.add_to_hash_chain(&value_from(i)).unwrap();
        let inserted = i + 1;
        let expected = if inserted == batch.zkp_batch_size {
            0
        } else {
            ((inserted - 1) % 3) as usize
        };
        assert_eq!(batch.num_pending(), expected, "after {inserted} inserts");
    }
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
