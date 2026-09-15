use zolana_tree::{
    error::TreeError, NullifierTreeInitParams, TreeAccount, TreeFeeSchedule, UTXO_TREE_HEIGHT,
};

fn init(bytes: &mut [u8]) -> TreeAccount<'_> {
    TreeAccount::init(
        bytes,
        7,
        UTXO_TREE_HEIGHT as u8,
        [2; 32],
        11,
        NullifierTreeInitParams::default(),
        TreeFeeSchedule::default(),
    )
    .expect("initialize tree")
}

#[test]
fn dummy_capacity_reserves_the_whole_state_tree_and_current_input_batch() {
    let mut bytes = vec![0; TreeAccount::account_size()];
    let mut tree = init(&mut bytes);
    // Outstanding UTXOs must remain covered even though these state leaves
    // are no longer free. Appending more outputs must never reopen the gate.
    for value in 1..=10 {
        tree.utxo_tree()
            .append([value; 32], 1)
            .expect("append UTXO");
    }
    let state_capacity = tree.utxo_tree().capacity();
    for input_count in [1, 2, 8, 36] {
        for (extra_capacity, allowed) in [(input_count - 1, false), (input_count, true)] {
            let nullifier = tree.nullifier_tree();
            nullifier.queue_next_index = nullifier.capacity - state_capacity - extra_capacity;
            assert_eq!(
                tree.allow_dummy_inputs(input_count),
                Ok(allowed),
                "{input_count} inputs with {extra_capacity} leaves above the reserve"
            );
        }
    }
    let nullifier = tree.nullifier_tree();
    nullifier.queue_next_index = nullifier.capacity - state_capacity;
    assert_eq!(tree.allow_dummy_inputs(1), Ok(false));
    tree.utxo_tree().append([11; 32], 2).expect("later deposit");
    assert_eq!(tree.allow_dummy_inputs(1), Ok(false));
}

#[test]
fn exhausted_nullifier_space_disallows_dummies_despite_free_state_leaves() {
    let mut bytes = vec![0; TreeAccount::account_size()];
    let mut tree = init(&mut bytes);
    let nullifier = tree.nullifier_tree();
    nullifier.queue_next_index = nullifier.capacity;
    assert_eq!(tree.allow_dummy_inputs(1), Ok(false));
}

#[test]
fn dummy_capacity_rejects_invalid_reservations() {
    let mut bytes = vec![0; TreeAccount::account_size()];
    let mut tree = init(&mut bytes);
    assert_eq!(
        tree.allow_dummy_inputs(u64::MAX),
        Err(TreeError::InvalidCapacity)
    );
    let nullifier = tree.nullifier_tree();
    nullifier.queue_next_index = nullifier.capacity + 1;
    assert_eq!(tree.allow_dummy_inputs(1), Err(TreeError::InvalidCapacity));
}
