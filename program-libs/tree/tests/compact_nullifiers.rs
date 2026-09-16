use zolana_tree::{NullifierTreeInitParams, TreeAccount, TreeFeeSchedule};

#[test]
fn migration_requires_drained_queue_and_retires_old_roots() {
    let mut bytes = vec![0; TreeAccount::account_size()];
    let mut tree = TreeAccount::init(
        &mut bytes,
        1,
        32,
        [7; 32],
        7,
        NullifierTreeInitParams::default(),
        TreeFeeSchedule::default(),
    )
    .unwrap();
    let root = tree.nullifier_tree().get_root().unwrap();
    tree.nullifier_tree().root_history.roots[7] = [3; 32];
    tree.nullifier_tree().queue_next_index = 251;
    assert!(tree.enable_compact_nullifiers().is_err());
    assert!(!tree.uses_compact_nullifiers());
    tree.nullifier_tree().next_index = 251;
    tree.enable_compact_nullifiers().unwrap();
    assert!(tree.uses_compact_nullifiers());
    assert_eq!(tree.close_before_index(), 251);
    assert_eq!(tree.get_nullifier_tree_root(0).unwrap(), root);
    assert!(tree.get_nullifier_tree_root(7).is_err());
    assert!(tree.enable_compact_nullifiers().is_err());
    drop(tree);
    assert!(TreeAccount::read_compact_nullifiers(&bytes).unwrap());
}
