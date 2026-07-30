use zolana_batched_merkle_tree::initialize_address_tree::InitAddressTreeAccountsInstructionData;
use zolana_tree::{
    error::TreeError,
    smt::{UtxoTreeLayout, ROOT_HISTORY_CAPACITY},
    TreeAccount, INITIALIZED,
};

// Must equal the pool's `POOL_UTXO_HEIGHT` (lib.rs) — `TreeAccount::init`
// rejects any other height with `HeightTooLarge`.
const HEIGHT: u8 = 32;
const DISCRIMINATOR: u8 = 7;

fn leaf(i: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = i;
    bytes
}

#[test]
fn init_then_reload() {
    let params = InitAddressTreeAccountsInstructionData::default();
    let mut bytes = vec![0u8; TreeAccount::account_size()];

    let pubkey = [2u8; 32];

    let appended_root = {
        let mut tree =
            TreeAccount::init(&mut bytes, DISCRIMINATOR, HEIGHT, pubkey, params).unwrap();

        assert_eq!(tree.discriminator(), DISCRIMINATOR);
        assert_eq!(tree.state(), INITIALIZED);
        assert_eq!(tree.utxo_tree().height(), HEIGHT as usize);
        assert_eq!(tree.utxo_tree().next_index(), 0);
        assert_eq!(tree.nullifer_tree().pubkey().to_bytes(), pubkey);

        let empty_root = tree.utxo_tree().root();
        assert_ne!(empty_root, [0u8; 32]);
        assert_eq!(tree.utxo_tree().current_root_index(), 0);
        assert_eq!(tree.utxo_tree().root_by_index(0).unwrap(), empty_root);

        tree.utxo_tree().append(leaf(1)).unwrap();
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
fn append_batch_matches_sequential() {
    let params = InitAddressTreeAccountsInstructionData::default();
    let pubkey = [2u8; 32];
    let count = 10u8;

    let mut seq_bytes = vec![0u8; TreeAccount::account_size()];
    let mut seq = TreeAccount::init(&mut seq_bytes, DISCRIMINATOR, HEIGHT, pubkey, params).unwrap();
    for i in 0..count {
        seq.utxo_tree().append(leaf(i + 1)).unwrap();
    }
    let seq_root = seq.utxo_tree().root();
    let seq_next = seq.utxo_tree().next_index();
    let seq_cursor = seq.utxo_tree().current_root_index();

    let mut batch_bytes = vec![0u8; TreeAccount::account_size()];
    let mut batch =
        TreeAccount::init(&mut batch_bytes, DISCRIMINATOR, HEIGHT, pubkey, params).unwrap();
    let leaves: Vec<[u8; 32]> = (0..count).map(|i| leaf(i + 1)).collect();
    batch.utxo_tree().append_batch(leaves.iter()).unwrap();

    // Root and leaf index match the sequential path exactly.
    assert_eq!(batch.utxo_tree().root(), seq_root);
    assert_eq!(batch.utxo_tree().next_index(), seq_next);
    // The batch pushes only its final root, so its cursor advances by one
    // while the sequential path pushed one real root per leaf.
    assert_eq!(seq_cursor, count as u16);
    let batch_cursor = batch.utxo_tree().current_root_index();
    assert_eq!(batch_cursor, 1);
    assert_eq!(
        batch.utxo_tree().root_by_index(batch_cursor).unwrap(),
        seq_root
    );
    // The batch history holds no zero placeholder slots.
    for index in 0..=batch_cursor {
        assert_ne!(batch.utxo_tree().root_by_index(index).unwrap(), [0u8; 32]);
    }
}

/// Untrusted nullifier params (from `create_tree` instruction data) must be
/// rejected with an error, not a division-by-zero or pow-overflow panic.
#[test]
fn init_rejects_invalid_nullifier_params() {
    let pubkey = [2u8; 32];
    let valid = InitAddressTreeAccountsInstructionData::default();
    let invalid = [
        InitAddressTreeAccountsInstructionData {
            input_queue_zkp_batch_size: 0,
            ..valid
        },
        InitAddressTreeAccountsInstructionData {
            input_queue_batch_size: 0,
            ..valid
        },
        InitAddressTreeAccountsInstructionData {
            input_queue_batch_size: valid.input_queue_zkp_batch_size + 1,
            ..valid
        },
        // Divisible and correct quotient, but no verifying key exists for
        // zkp batch size 100: the tree could never be forested.
        InitAddressTreeAccountsInstructionData {
            input_queue_batch_size: 12_000,
            input_queue_zkp_batch_size: 100,
            ..valid
        },
        InitAddressTreeAccountsInstructionData {
            height: 30,
            ..valid
        },
        InitAddressTreeAccountsInstructionData {
            root_history_capacity: 1,
            ..valid
        },
    ];
    for params in invalid {
        let mut bytes = vec![0u8; TreeAccount::account_size()];
        let err = TreeAccount::init(&mut bytes, DISCRIMINATOR, HEIGHT, pubkey, params)
            .err()
            .expect("invalid params must be rejected");
        assert!(
            matches!(err, TreeError::AddressInit),
            "params {params:?} failed with {err:?}, expected AddressInit"
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
        layout.append(leaf(i + 1)).unwrap();
    }
    assert_eq!(layout.next_index(), 4);

    // Single and batch appends past capacity fail instead of corrupting the
    // tree; the root stays at the full-tree root.
    let full_root = layout.root();
    assert_eq!(layout.append(leaf(5)), Err(TreeError::TreeIsFull));
    assert_eq!(
        layout.append_batch([leaf(6), leaf(7)].iter()),
        Err(TreeError::TreeIsFull)
    );
    assert_eq!(layout.next_index(), 4);
    assert_eq!(layout.root(), full_root);
}

#[test]
fn root_history_wraps_around() {
    let params = InitAddressTreeAccountsInstructionData::default();
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = TreeAccount::init(&mut bytes, DISCRIMINATOR, HEIGHT, [2u8; 32], params).unwrap();

    // Append past capacity so the ring buffer wraps. Cursor starts at 0 (the
    // empty root), so after N appends it sits at N % capacity.
    let appends = ROOT_HISTORY_CAPACITY + 5;
    let mut roots = Vec::with_capacity(appends);
    for i in 0..appends {
        tree.utxo_tree().append(leaf((i % 200 + 1) as u8)).unwrap();
        roots.push(tree.utxo_tree().root());
    }

    let cursor = appends % ROOT_HISTORY_CAPACITY;
    assert_eq!(tree.utxo_tree().current_root_index(), cursor as u16);

    // The latest root lives at the wrapped cursor.
    assert_eq!(
        tree.utxo_tree().root_by_index(cursor as u16).unwrap(),
        *roots.last().unwrap()
    );

    // Index 0 held the empty root, then was overwritten on the wrap (append
    // number `capacity`), so it now returns that newer root, not the empty one.
    assert_eq!(
        tree.utxo_tree().root_by_index(0).unwrap(),
        roots[ROOT_HISTORY_CAPACITY - 1]
    );

    // A slot just ahead of the cursor still holds a pre-wrap root (oldest live
    // entry), proving the window slid rather than reset.
    let oldest = (cursor + 1) % ROOT_HISTORY_CAPACITY;
    assert_eq!(
        tree.utxo_tree().root_by_index(oldest as u16).unwrap(),
        roots[oldest - 1]
    );
}
