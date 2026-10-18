use core::mem::size_of;

use zolana_tree::{
    nullifier_tree::init::match_circuit_size, NullifierTreeInitParams, TreeAccount,
    TreeAccountLayout, TreeFeeSchedule, INITIALIZED, UTXO_TREE_HEIGHT,
};

type DeployedLayout = TreeAccountLayout<UTXO_TREE_HEIGHT, 100>;

#[test]
fn deployed_250_batch_tree_loads_and_preserves_its_layout() {
    let mut bytes = vec![0u8; size_of::<DeployedLayout>()];
    let layout: &mut DeployedLayout = wincode::deserialize_mut(&mut bytes).unwrap();
    layout.discriminator = 1;
    layout.state = INITIALIZED;
    layout.tree_id = 17;
    layout.fees = TreeFeeSchedule::at_cost(250, 5_000, 88).unwrap();
    layout.fee_balance = 123_456;
    layout.utxo.init(UTXO_TREE_HEIGHT).unwrap();
    layout.utxo.append([1u8; 32], 7).unwrap();
    layout.nullifier.init(25_000, 250, 40).unwrap();
    layout.nullifier.root_history.current_index = 99;
    *layout.nullifier.root_history.roots.get_mut(98).unwrap() = [2u8; 32];
    for value in 1u16..=251 {
        let mut nullifier = [0u8; 32];
        nullifier
            .get_mut(30..)
            .unwrap()
            .copy_from_slice(&value.to_be_bytes());
        layout
            .nullifier
            .insert_nullifier_into_queue(&nullifier)
            .unwrap();
    }

    let before = bytes.clone();
    let mut expected = bytes.clone();
    let next_nullifier = [3u8; 32];
    let expected_layout: &mut DeployedLayout = wincode::deserialize_mut(&mut expected).unwrap();
    expected_layout
        .nullifier
        .insert_nullifier_into_queue(&next_nullifier)
        .unwrap();

    {
        let tree = TreeAccount::from_bytes(&mut bytes, [4u8; 32]).unwrap();
        assert_eq!(tree.tree_id(), 17);
        assert_eq!(tree.get_nullifier_tree_root(98).unwrap(), [2u8; 32]);
    }
    assert_eq!(
        bytes, before,
        "loading must not mutate the deployed account"
    );
    TreeAccount::from_bytes(&mut bytes, [4u8; 32])
        .unwrap()
        .nullifier_tree()
        .insert_nullifier_into_queue(&next_nullifier)
        .unwrap();
    assert_eq!(
        bytes, expected,
        "queue writes must preserve the deployed layout"
    );
}

#[test]
fn new_batch_size_keeps_one_hundred_slots_and_the_deployed_account_size() {
    let params = NullifierTreeInitParams::default();
    assert_eq!(params.input_queue_zkp_batch_size, 4999);
    assert_eq!(params.input_queue_batch_size, 499_900);
    assert_eq!(TreeAccount::account_size(), size_of::<DeployedLayout>());
    assert!(
        match_circuit_size(250),
        "active trees still need 250-batch proofs"
    );
    assert!(match_circuit_size(4999));

    for batch_size in [250, 4999] {
        let mut bytes = vec![0u8; size_of::<DeployedLayout>()];
        let mut tree = TreeAccount::init(
            &mut bytes,
            1,
            UTXO_TREE_HEIGHT as u8,
            [4u8; 32],
            17,
            NullifierTreeInitParams {
                input_queue_batch_size: batch_size * 100,
                input_queue_zkp_batch_size: batch_size,
                height: 40,
            },
            TreeFeeSchedule::default(),
        )
        .unwrap();
        assert_eq!(tree.nullifier_tree().capacity, 1u64 << 40);
        assert_eq!(tree.nullifier_tree().root_history.roots.len(), 100);
    }
}
