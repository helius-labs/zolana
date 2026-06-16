use light_batched_merkle_tree::initialize_address_tree::InitAddressTreeAccountsInstructionData;
use zolana_tree::smt::ROOT_HISTORY_CAPACITY;
use zolana_tree::TreeAccount;

const HEIGHT: u8 = 26;
const DISCRIMINATOR: u8 = 7;

fn leaf(i: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = i;
    bytes
}

#[test]
fn init_then_reload() {
    let params = InitAddressTreeAccountsInstructionData::default();
    let mut bytes = vec![0u8; TreeAccount::account_size(HEIGHT, params)];

    let owner = [1u8; 32];
    let pubkey = [2u8; 32];

    let appended_root = {
        let mut tree =
            TreeAccount::init(&mut bytes, DISCRIMINATOR, HEIGHT, owner, pubkey, params).unwrap();

        assert_eq!(tree.discriminator, DISCRIMINATOR);
        assert_eq!(tree.utxo_tree.height(), HEIGHT as usize);
        assert_eq!(tree.utxo_tree.next_index(), 0);

        let empty_root = tree.utxo_tree.root();
        assert_ne!(empty_root, [0u8; 32]);
        // History starts with the empty root at index 0.
        assert_eq!(tree.utxo_tree.current_root_index(), 0);
        assert_eq!(tree.utxo_tree.root_by_index(0).unwrap(), empty_root);

        tree.utxo_tree.append(leaf(1));
        assert_eq!(tree.utxo_tree.next_index(), 1);
        let appended_root = tree.utxo_tree.root();
        assert_ne!(appended_root, empty_root);
        // Append pushed the new root to index 1; the empty root is still at 0.
        assert_eq!(tree.utxo_tree.current_root_index(), 1);
        assert_eq!(tree.utxo_tree.root_by_index(1).unwrap(), appended_root);
        assert_eq!(tree.utxo_tree.root_by_index(0).unwrap(), empty_root);
        appended_root
    };

    let tree = TreeAccount::from_bytes(&mut bytes, pubkey).unwrap();
    assert_eq!(tree.discriminator, DISCRIMINATOR);
    assert_eq!(tree.utxo_tree.height(), HEIGHT as usize);
    assert_eq!(tree.utxo_tree.next_index(), 1);
    assert_eq!(tree.utxo_tree.root(), appended_root);
    // Root history survives the reload.
    assert_eq!(tree.utxo_tree.current_root_index(), 1);
    assert_eq!(tree.utxo_tree.root_by_index(1).unwrap(), appended_root);
}

#[test]
fn root_history_wraps_around() {
    let params = InitAddressTreeAccountsInstructionData::default();
    let mut bytes = vec![0u8; TreeAccount::account_size(HEIGHT, params)];
    let mut tree = TreeAccount::init(
        &mut bytes,
        DISCRIMINATOR,
        HEIGHT,
        [1u8; 32],
        [2u8; 32],
        params,
    )
    .unwrap();

    // Append past capacity so the ring buffer wraps. Cursor starts at 0 (the
    // empty root), so after N appends it sits at N % capacity.
    let appends = ROOT_HISTORY_CAPACITY + 5;
    let mut roots = Vec::with_capacity(appends);
    for i in 0..appends {
        tree.utxo_tree.append(leaf((i % 200 + 1) as u8));
        roots.push(tree.utxo_tree.root());
    }

    let cursor = appends % ROOT_HISTORY_CAPACITY;
    assert_eq!(tree.utxo_tree.current_root_index(), cursor as u16);

    // The latest root lives at the wrapped cursor.
    assert_eq!(
        tree.utxo_tree.root_by_index(cursor as u16).unwrap(),
        *roots.last().unwrap()
    );

    // Index 0 held the empty root, then was overwritten on the wrap (append
    // number `capacity`), so it now returns that newer root, not the empty one.
    assert_eq!(
        tree.utxo_tree.root_by_index(0).unwrap(),
        roots[ROOT_HISTORY_CAPACITY - 1]
    );

    // A slot just ahead of the cursor still holds a pre-wrap root (oldest live
    // entry), proving the window slid rather than reset.
    let oldest = (cursor + 1) % ROOT_HISTORY_CAPACITY;
    assert_eq!(
        tree.utxo_tree.root_by_index(oldest as u16).unwrap(),
        roots[oldest - 1]
    );
}
