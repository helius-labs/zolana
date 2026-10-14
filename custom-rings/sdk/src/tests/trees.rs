use solana_address::Address;
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::utxo::SppProofInputUtxo;

use super::support::{input, ring, tree_account, Accounts};
use crate::{
    tree_id,
    trees::{bind_trees, input_groups, read_tree, spend_trees, TransactRoots, TreeView},
    PoolTree, RingError,
};

fn view(id: u16, headroom: u64) -> TreeView {
    TreeView {
        tree: PoolTree::from_id(id),
        headroom,
        roots: TransactRoots {
            state: [0; 32],
            state_index: 0,
            nullifier: [0; 32],
            nullifier_index: 0,
        },
    }
}

fn spends(trees: &[u16]) -> Vec<SppProofInputUtxo> {
    let owner = ShieldedKeypair::new_ed25519().unwrap();
    trees
        .iter()
        .map(|&tree_id| input(&owner, 1, tree_id, Some(ring().program_id())))
        .collect()
}

#[test]
fn input_groups_count_every_slot_in_first_use_order() {
    let mut inputs = spends(&[4, 9, 4]);
    inputs.push(SppProofInputUtxo::dummy(9).unwrap());
    assert_eq!(input_groups(&inputs), vec![(4, 2), (9, 2)]);
}

#[test]
fn spend_trees_allow_dummies_only_when_every_group_has_headroom() {
    let groups = input_groups(&spends(&[4, 9, 9]));
    let trees = bind_trees(&groups, &[view(4, 1), view(9, 2)], &view(4, 0), 4).unwrap();
    assert_eq!(
        trees.inputs,
        vec![PoolTree::from_id(4).address, PoolTree::from_id(9).address]
    );
    assert_eq!(trees.output, PoolTree::from_id(4).address);
    assert!(trees.allow_dummy_inputs);
    assert!(
        !bind_trees(&groups, &[view(4, 1), view(9, 1)], &view(4, 0), 4)
            .unwrap()
            .allow_dummy_inputs
    );
    assert!(matches!(
        bind_trees(&groups, &[view(4, 1), view(8, 2)], &view(4, 0), 4),
        Err(RingError::TreeIdMismatch {
            expected: 8,
            found: 9,
            ..
        })
    ));
    assert!(matches!(
        bind_trees(&groups, &[view(4, 1), view(9, 2)], &view(5, 0), 4),
        Err(RingError::TreeIdMismatch {
            expected: 5,
            found: 4,
            ..
        })
    ));
}

#[tokio::test]
async fn a_tree_reads_only_from_a_pool_tree_account() {
    let tree = PoolTree::from_id(7);
    let valid = Accounts::default().with(tree.address, tree_account(tree));
    let view = read_tree(&valid, tree.address).await.unwrap();
    assert_eq!(view.tree, tree);
    assert_eq!(tree_id(&valid, tree.address).await.unwrap(), 7);

    let missing = Accounts::default();
    assert!(matches!(
        read_tree(&missing, tree.address).await,
        Err(RingError::MissingTree { address }) if address == tree.address
    ));
    let mut foreign = tree_account(tree);
    foreign.owner = Address::new_from_array([9; 32]);
    let mut wrong_discriminator = tree_account(tree);
    wrong_discriminator.data[0] ^= 1;
    for account in [foreign, wrong_discriminator] {
        let rpc = Accounts::default().with(tree.address, account);
        assert!(matches!(
            read_tree(&rpc, tree.address).await,
            Err(RingError::InvalidTree { address }) if address == tree.address
        ));
    }
}

#[tokio::test]
async fn a_tree_account_under_another_id_is_refused_before_proving() {
    let inputs = spends(&[4]);
    let four = PoolTree::from_id(4);
    let rpc = Accounts::default().with(four.address, tree_account(four));
    let trees = spend_trees(&rpc, &inputs, 4).await.unwrap();
    assert_eq!(trees.inputs, vec![four.address]);
    // The account at tree 4's address holds tree 5.
    let swapped = Accounts::default().with(
        four.address,
        tree_account(PoolTree {
            address: four.address,
            id: 5,
        }),
    );
    assert!(matches!(
        spend_trees(&swapped, &inputs, 4).await,
        Err(RingError::TreeIdMismatch {
            expected: 5,
            found: 4,
            ..
        })
    ));
}
