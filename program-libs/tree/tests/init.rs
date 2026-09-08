use zolana_hasher::primitives::BN254_SCALAR_MODULUS_BE;
use zolana_tree::{
    error::TreeError,
    smt::{UtxoTreeLayout, ROOT_HISTORY_CAPACITY},
    NullifierTreeInitParams, TreeAccount, TreeFeeSchedule, INITIALIZED,
};

// Must equal the pool's `UTXO_TREE_HEIGHT` (lib.rs) — `TreeAccount::init`
// rejects any other height with `HeightTooLarge`.
const HEIGHT: u8 = 32;
const DISCRIMINATOR: u8 = 7;
const TREE_ID: u16 = 11;
const FEES: TreeFeeSchedule = TreeFeeSchedule {
    fee_per_nullifier: 190,
    append_reimbursement: 5_000,
    close_reimbursement: 170,
};

fn leaf(i: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = i;
    bytes
}

#[test]
fn init_then_reload() {
    let params = NullifierTreeInitParams::default();
    let mut bytes = vec![0u8; TreeAccount::account_size()];

    let pubkey = [2u8; 32];

    let appended_root = {
        let mut tree = TreeAccount::init(
            &mut bytes,
            DISCRIMINATOR,
            HEIGHT,
            pubkey,
            TREE_ID,
            params,
            FEES,
        )
        .unwrap();

        assert_eq!(tree.discriminator(), DISCRIMINATOR);
        assert_eq!(tree.state(), INITIALIZED);
        assert_eq!(tree.utxo_tree().height(), HEIGHT as usize);
        assert_eq!(tree.utxo_tree().next_index(), 0);
        assert_eq!(tree.pubkey(), pubkey);
        assert_eq!(tree.tree_id(), TREE_ID);

        let empty_root = tree.utxo_tree().root();
        assert_ne!(empty_root, [0u8; 32]);
        assert_eq!(tree.utxo_tree().current_root_index(), 0);
        assert_eq!(tree.utxo_tree().root_by_index(0).unwrap(), empty_root);
        assert_eq!(
            tree.utxo_tree().root_history_capacity,
            ROOT_HISTORY_CAPACITY as u16
        );

        tree.utxo_tree().append(leaf(1), 1).unwrap();
        assert_eq!(tree.utxo_tree().next_index(), 1);
        let appended_root = tree.utxo_tree().root();
        assert_ne!(appended_root, empty_root);
        // Append pushed the new root to index 1; the empty root is still at 0.
        assert_eq!(tree.utxo_tree().current_root_index(), 1);
        assert_eq!(tree.utxo_tree().root_by_index(1).unwrap(), appended_root);
        assert_eq!(tree.utxo_tree().root_by_index(0).unwrap(), empty_root);
        appended_root
    };

    let mut tree = TreeAccount::from_bytes(&mut bytes, pubkey).unwrap();
    assert_eq!(tree.discriminator(), DISCRIMINATOR);
    assert_eq!(tree.state(), INITIALIZED);
    assert_eq!(tree.utxo_tree().height(), HEIGHT as usize);
    assert_eq!(tree.utxo_tree().next_index(), 1);
    assert_eq!(tree.utxo_tree().root(), appended_root);
    // Root history survives the reload.
    assert_eq!(tree.utxo_tree().current_root_index(), 1);
    assert_eq!(tree.utxo_tree().root_by_index(1).unwrap(), appended_root);
}

#[test]
fn append_rejects_a_non_canonical_leaf() {
    let params = NullifierTreeInitParams::default();
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = TreeAccount::init(
        &mut bytes,
        DISCRIMINATOR,
        HEIGHT,
        [2u8; 32],
        TREE_ID,
        params,
        FEES,
    )
    .unwrap();
    let root_before = tree.utxo_tree().root();

    assert_eq!(
        tree.utxo_tree().append(BN254_SCALAR_MODULUS_BE, 1),
        Err(TreeError::Hash)
    );
    assert_eq!(tree.utxo_tree().root(), root_before);
    assert_eq!(tree.utxo_tree().next_index(), 0);
}

#[test]
fn reload_rejects_inconsistent_nullifier_batch_metadata() {
    let params = NullifierTreeInitParams::default();
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let pubkey = [2u8; 32];

    {
        let mut tree = TreeAccount::init(
            &mut bytes,
            DISCRIMINATOR,
            HEIGHT,
            pubkey,
            TREE_ID,
            params,
            FEES,
        )
        .unwrap();
        tree.nullifier_tree().batches[0].batch_size += 1;
    }

    assert_eq!(
        TreeAccount::from_bytes(&mut bytes, pubkey).err().unwrap(),
        TreeError::Deserialize
    );
}

#[test]
fn reload_rejects_incorrect_state_root_history_capacity() {
    let params = NullifierTreeInitParams::default();
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let pubkey = [2u8; 32];

    {
        let mut tree = TreeAccount::init(
            &mut bytes,
            DISCRIMINATOR,
            HEIGHT,
            pubkey,
            TREE_ID,
            params,
            FEES,
        )
        .unwrap();
        tree.utxo_tree().root_history_capacity = 499;
    }

    assert_eq!(
        TreeAccount::from_bytes(&mut bytes, pubkey).err().unwrap(),
        TreeError::Deserialize
    );
}

#[test]
fn reload_rejects_inconsistent_state_root_history_metadata() {
    let params = NullifierTreeInitParams::default();
    let pubkey = [2u8; 32];
    let corruptions: [fn(&mut UtxoTreeLayout<32>); 3] = [
        |tree| tree.root_history_cursor = ROOT_HISTORY_CAPACITY as u16,
        |tree| tree.root_history_len = 0,
        // Before the history fills, cursor + 1 must equal its dense length.
        |tree| tree.root_history_len = 2,
    ];

    for corrupt in corruptions {
        let mut bytes = vec![0u8; TreeAccount::account_size()];
        {
            let mut tree = TreeAccount::init(
                &mut bytes,
                DISCRIMINATOR,
                HEIGHT,
                pubkey,
                TREE_ID,
                params,
                FEES,
            )
            .unwrap();
            corrupt(tree.utxo_tree());
        }

        assert_eq!(
            TreeAccount::from_bytes(&mut bytes, pubkey).err().unwrap(),
            TreeError::Deserialize
        );
    }
}

#[test]
fn append_batch_matches_sequential() {
    let params = NullifierTreeInitParams::default();
    let pubkey = [2u8; 32];
    let count = 10u8;
    // Slot zero exercises the first-update marker: a multi-leaf first batch
    // must advance to index 1 even though `last_update_slot` initializes to 0.
    let slot = 0;

    let mut seq_bytes = vec![0u8; TreeAccount::account_size()];
    let mut seq = TreeAccount::init(
        &mut seq_bytes,
        DISCRIMINATOR,
        HEIGHT,
        pubkey,
        TREE_ID,
        params,
        FEES,
    )
    .unwrap();
    for i in 0..count {
        seq.utxo_tree().append(leaf(i + 1), slot).unwrap();
    }
    let seq_root = seq.utxo_tree().root();
    let seq_next = seq.utxo_tree().next_index();
    let seq_cursor = seq.utxo_tree().current_root_index();

    let mut batch_bytes = vec![0u8; TreeAccount::account_size()];
    let mut batch = TreeAccount::init(
        &mut batch_bytes,
        DISCRIMINATOR,
        HEIGHT,
        pubkey,
        TREE_ID,
        params,
        FEES,
    )
    .unwrap();
    let leaves: Vec<[u8; 32]> = (0..count).map(|i| leaf(i + 1)).collect();
    batch.utxo_tree().append_batch(leaves.iter(), slot).unwrap();

    // Root and leaf index match the sequential path exactly.
    assert_eq!(batch.utxo_tree().root(), seq_root);
    assert_eq!(batch.utxo_tree().next_index(), seq_next);
    // Every append in the slot overwrites the same history entry. A batch and
    // sequential appends therefore expose only the slot-final root.
    assert_eq!(seq_cursor, 1);
    let batch_cursor = batch.utxo_tree().current_root_index();
    assert_eq!(batch_cursor, 1);
    assert_eq!(
        batch.utxo_tree().root_by_index(batch_cursor).unwrap(),
        seq_root
    );
    assert_eq!(
        batch.utxo_tree().root_by_index(2),
        Err(TreeError::InvalidRootIndex)
    );
    assert_eq!(batch.utxo_tree().root_history_len, 2);
    assert_eq!(batch.utxo_tree().last_update_slot, slot);
}

/// Untrusted nullifier params (from `create_tree` instruction data) must be
/// rejected with an error, not a division-by-zero or pow-overflow panic.
#[test]
fn init_rejects_invalid_nullifier_params() {
    let pubkey = [2u8; 32];
    let valid = NullifierTreeInitParams::default();
    let invalid = [
        NullifierTreeInitParams {
            input_queue_zkp_batch_size: 0,
            ..valid
        },
        NullifierTreeInitParams {
            input_queue_batch_size: 0,
            ..valid
        },
        NullifierTreeInitParams {
            input_queue_batch_size: valid.input_queue_zkp_batch_size + 1,
            ..valid
        },
        // Divisible and correct quotient, but no verifying key exists for
        // zkp batch size 100: the tree could never be forested.
        NullifierTreeInitParams {
            input_queue_batch_size: 12_000,
            input_queue_zkp_batch_size: 100,
            ..valid
        },
        NullifierTreeInitParams {
            height: 30,
            ..valid
        },
    ];
    for params in invalid {
        let mut bytes = vec![0u8; TreeAccount::account_size()];
        let err = TreeAccount::init(
            &mut bytes,
            DISCRIMINATOR,
            HEIGHT,
            pubkey,
            TREE_ID,
            params,
            FEES,
        )
        .err()
        .expect("invalid params must be rejected");
        assert!(
            matches!(err, TreeError::NullifierInit),
            "params {params:?} failed with {err:?}, expected NullifierInit"
        );
    }
}

#[test]
fn append_fails_when_tree_is_full() {
    const SMALL_HEIGHT: usize = 2;
    let mut bytes = vec![0u8; core::mem::size_of::<UtxoTreeLayout<SMALL_HEIGHT>>()];
    let layout: &mut UtxoTreeLayout<SMALL_HEIGHT> = wincode::deserialize_mut(&mut bytes).unwrap();
    layout.init(SMALL_HEIGHT).unwrap();
    assert_eq!(layout.capacity(), 4);

    for i in 0..4u8 {
        layout.append(leaf(i + 1), u64::from(i) + 1).unwrap();
    }
    assert_eq!(layout.next_index(), 4);

    // Single and batch appends past capacity fail instead of corrupting the
    // tree; the root stays at the full-tree root.
    let full_root = layout.root();
    assert_eq!(layout.append(leaf(5), 5), Err(TreeError::TreeIsFull));
    assert_eq!(
        layout.append_batch([leaf(6), leaf(7)].iter(), 6),
        Err(TreeError::TreeIsFull)
    );
    assert_eq!(layout.next_index(), 4);
    assert_eq!(layout.root(), full_root);
}

#[test]
fn same_slot_appends_overwrite_one_history_entry() {
    let params = NullifierTreeInitParams::default();
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = TreeAccount::init(
        &mut bytes,
        DISCRIMINATOR,
        HEIGHT,
        [2u8; 32],
        TREE_ID,
        params,
        FEES,
    )
    .unwrap();

    let empty_root = tree.utxo_tree().root();
    let slot = 123;
    tree.utxo_tree().append(leaf(1), slot).unwrap();
    let first_root = tree.utxo_tree().root();
    for i in 1..200 {
        tree.utxo_tree()
            .append(leaf((i % 200 + 1) as u8), slot)
            .unwrap();
    }

    let final_root = tree.utxo_tree().root();
    assert_ne!(final_root, first_root);
    assert_eq!(tree.utxo_tree().current_root_index(), 1);
    assert_eq!(tree.utxo_tree().root_by_index(1).unwrap(), final_root);
    assert_eq!(tree.utxo_tree().root_by_index(0).unwrap(), empty_root);
    assert_eq!(
        tree.utxo_tree().root_by_index(2),
        Err(TreeError::InvalidRootIndex)
    );
    assert_eq!(tree.utxo_tree().root_history_len, 2);
}

#[test]
fn root_history_supports_adjacent_and_skipped_slots() {
    let params = NullifierTreeInitParams::default();
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = TreeAccount::init(
        &mut bytes,
        DISCRIMINATOR,
        HEIGHT,
        [2u8; 32],
        TREE_ID,
        params,
        FEES,
    )
    .unwrap();

    tree.utxo_tree().append(leaf(1), 7).unwrap();
    let slot_7_root = tree.utxo_tree().root();
    tree.utxo_tree().append(leaf(2), 8).unwrap();
    let slot_8_root = tree.utxo_tree().root();
    tree.utxo_tree().append(leaf(3), 499).unwrap();
    let slot_499_root = tree.utxo_tree().root();

    assert_eq!(tree.utxo_tree().current_root_index(), 3);
    assert_eq!(tree.utxo_tree().root_by_index(1).unwrap(), slot_7_root);
    assert_eq!(tree.utxo_tree().root_by_index(2).unwrap(), slot_8_root);
    assert_eq!(tree.utxo_tree().root_by_index(3).unwrap(), slot_499_root);
    assert_eq!(
        tree.utxo_tree().root_by_index(4),
        Err(TreeError::InvalidRootIndex)
    );
    assert_eq!(tree.utxo_tree().root_history_len, 4);
    assert_eq!(
        tree.utxo_tree().root_history_capacity,
        ROOT_HISTORY_CAPACITY as u16
    );
}

#[test]
fn root_history_rejects_a_slot_regression_without_mutating_the_tree() {
    let params = NullifierTreeInitParams::default();
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = TreeAccount::init(
        &mut bytes,
        DISCRIMINATOR,
        HEIGHT,
        [2u8; 32],
        TREE_ID,
        params,
        FEES,
    )
    .unwrap();

    tree.utxo_tree().append(leaf(1), 9).unwrap();
    let root = tree.utxo_tree().root();
    let next_index = tree.utxo_tree().next_index();
    let root_index = tree.utxo_tree().current_root_index();

    assert_eq!(
        tree.utxo_tree().append(leaf(2), 8),
        Err(TreeError::InvalidUpdateSlot)
    );
    assert_eq!(tree.utxo_tree().root(), root);
    assert_eq!(tree.utxo_tree().next_index(), next_index);
    assert_eq!(tree.utxo_tree().current_root_index(), root_index);
    assert_eq!(tree.utxo_tree().last_update_slot, 9);
}

#[test]
fn root_history_retains_a_root_for_500_slots() {
    let params = NullifierTreeInitParams::default();
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = TreeAccount::init(
        &mut bytes,
        DISCRIMINATOR,
        HEIGHT,
        [2u8; 32],
        TREE_ID,
        params,
        FEES,
    )
    .unwrap();

    let first_slot = 10_000;
    tree.utxo_tree().append(leaf(1), first_slot).unwrap();
    let first_root = tree.utxo_tree().root();
    let first_index = tree.utxo_tree().current_root_index();

    for offset in 1..ROOT_HISTORY_CAPACITY as u64 {
        tree.utxo_tree()
            .append(leaf((offset % 200 + 1) as u8), first_slot + offset)
            .unwrap();
    }

    // The root remains accepted after updates in each of the following 499
    // slots.
    assert_eq!(
        tree.utxo_tree().root_by_index(first_index).unwrap(),
        first_root
    );
    assert_eq!(
        tree.utxo_tree().root_history_len,
        ROOT_HISTORY_CAPACITY as u16
    );

    // The 500th subsequent updated slot wraps to the same entry and evicts it.
    tree.utxo_tree()
        .append(leaf(2), first_slot + ROOT_HISTORY_CAPACITY as u64)
        .unwrap();
    let replacement_root = tree.utxo_tree().root();
    assert_ne!(replacement_root, first_root);
    assert_eq!(tree.utxo_tree().current_root_index(), first_index);
    assert_eq!(
        tree.utxo_tree().root_by_index(first_index).unwrap(),
        replacement_root
    );
}
