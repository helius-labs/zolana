use zolana_tree::{NullifierFilterMode, NullifierTreeInitParams, TreeAccount, TreeFeeSchedule};

fn init(bytes: &mut [u8]) -> TreeAccount<'_> {
    TreeAccount::init(
        bytes,
        1,
        32,
        [7; 32],
        7,
        NullifierTreeInitParams::default(),
        TreeFeeSchedule::default(),
    )
    .unwrap()
}

#[test]
fn enabling_requires_compact_guard_and_genesis_nullifiers() {
    let mut bytes = vec![0; TreeAccount::account_size()];
    let mut tree = init(&mut bytes);
    assert_eq!(tree.nullifier_tree().next_index, 1);
    assert_eq!(tree.nullifier_tree().queue_next_index, 1);
    assert_eq!(tree.nullifier_filter_mode(), NullifierFilterMode::Off);
    assert!(tree.enable_nullifier_filter().is_err());
    tree.enable_compact_nullifiers().unwrap();
    tree.utxo_tree()
        .append_batch([&[1; 32], &[2; 32]], 0)
        .unwrap();
    tree.enable_nullifier_filter().unwrap();
    assert_eq!(tree.nullifier_filter_mode(), NullifierFilterMode::Active);
    assert!(tree.enable_nullifier_filter().is_err());
    drop(tree);
    assert_eq!(
        TreeAccount::read_nullifier_filter_mode(&bytes).unwrap(),
        NullifierFilterMode::Active
    );
}

#[test]
fn historical_spends_cannot_enable_an_empty_filter() {
    for (inserted, queued) in [(1, 2), (2, 2), (2, 3)] {
        let mut bytes = vec![0; TreeAccount::account_size()];
        let mut tree = init(&mut bytes);
        tree.enable_compact_nullifiers().unwrap();
        tree.nullifier_tree().next_index = inserted;
        tree.nullifier_tree().queue_next_index = queued;
        assert!(tree.enable_nullifier_filter().is_err());
        assert_eq!(tree.nullifier_filter_mode(), NullifierFilterMode::Off);
    }
}

#[test]
fn retiring_is_irreversible_even_before_the_first_spend() {
    let mut bytes = vec![0; TreeAccount::account_size()];
    let mut tree = init(&mut bytes);
    assert!(tree.retire_nullifier_filter().is_err());
    tree.enable_compact_nullifiers().unwrap();
    tree.enable_nullifier_filter().unwrap();
    tree.retire_nullifier_filter().unwrap();
    assert_eq!(tree.nullifier_filter_mode(), NullifierFilterMode::Retired);
    assert!(tree.enable_nullifier_filter().is_err());
    assert!(tree.retire_nullifier_filter().is_err());
    assert!(tree.uses_compact_nullifiers());
    drop(tree);
    assert_eq!(
        TreeAccount::read_nullifier_filter_mode(&bytes).unwrap(),
        NullifierFilterMode::Retired
    );
}

#[test]
fn invalid_modes_and_active_without_pending_guard_fail_closed() {
    let mut bytes = vec![0; TreeAccount::account_size()];
    drop(init(&mut bytes));
    let offset = std::mem::offset_of!(zolana_tree::SppTreeLayout, _reserved);
    for mode in [1, 2, 3, 255] {
        bytes[offset + 1] = mode;
        assert!(TreeAccount::read_nullifier_filter_mode(&bytes).is_err());
        assert!(TreeAccount::from_bytes(&mut bytes, [7; 32]).is_err());
    }
    assert!(TreeAccount::read_nullifier_filter_mode(&[]).is_err());
}
