use solana_signer::Signer;
use solana_system_interface::error::SystemError;
use zolana_program_test::{Rejection, ZolanaProgramTest};

use shielded_pool_tests::support::fixtures::Pool;

#[test]
fn sol_deposit_rejects_insufficient_lamports_without_changing_root() {
    let mut pool = Pool::initialized();
    let poor = pool.funded_signer(2_000_000);
    let tree = pool.tree.pubkey();
    let root_before = pool.rpc.state_root(&tree).expect("root");

    let err = pool
        .rpc
        .deposit_sol(&tree, &poor, 100_000_000_000, [6u8; 32], [6u8; 32])
        .expect_err("unaffordable deposit must fail");
    Rejection::custom(SystemError::ResultWithNegativeLamports as u32).assert_litesvm(err);
    assert_eq!(pool.rpc.state_root(&tree), Some(root_before));
}

#[test]
fn repeated_sol_deposit_data_creates_distinct_leaves() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(1_000_000_000);
    let tree = pool.tree.pubkey();
    let data = ZolanaProgramTest::sol_shield_data(1_000_000, [7u8; 32], [7u8; 32]);
    let root0 = pool.rpc.state_root(&tree).expect("root");
    pool.rpc
        .deposit(&tree, &depositor, &data)
        .expect("first deposit");
    let root1 = pool.rpc.state_root(&tree).expect("root");
    pool.rpc.svm.expire_blockhash();
    pool.rpc
        .deposit(&tree, &depositor, &data)
        .expect("second deposit");
    let root2 = pool.rpc.state_root(&tree).expect("root");
    assert_ne!(root0, root1);
    assert_ne!(root1, root2);
    assert_eq!(pool.rpc.indexer().utxos().len(), 2);
    assert_eq!(pool.rpc.indexer().root(), root2);
}

#[test]
fn unpaused_tree_accepts_sol_deposit_after_pause() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(2_000_000_000);
    let tree = pool.tree.pubkey();
    pool.rpc
        .pause_tree(&pool.authority, &pool.tree, true)
        .expect("pause tree");
    pool.rpc
        .pause_tree(&pool.authority, &pool.tree, false)
        .expect("unpause tree");

    pool.rpc
        .deposit_sol(&tree, &depositor, 1_000_000, [5u8; 32], [5u8; 32])
        .expect("deposit after unpause");
}
