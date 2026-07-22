use solana_signer::Signer;
use zolana_interface::error::ShieldedPoolError;
use zolana_program_test::Rejection;
use zolana_test_utils::backend::LiteSvmPoolBackend;

#[test]
fn pause_blocks_tree_mutation_and_unpause_restores_it() {
    let mut backend = LiteSvmPoolBackend::initialized();
    let depositor = backend.funded_signer(2_000_000_000);
    let tree = backend.tree.pubkey();

    backend
        .rpc
        .pause_tree(&backend.authority, &backend.tree, true)
        .expect("pause tree");
    let root = backend.rpc.state_root(&tree).expect("tree root");
    let error = backend
        .rpc
        .deposit_sol(&tree, &depositor, 1_000_000, [1; 32], [2; 31])
        .expect_err("paused tree must reject deposit");
    Rejection::pool(ShieldedPoolError::TreePaused).assert_litesvm(error);
    assert_eq!(backend.rpc.state_root(&tree), Some(root));

    backend
        .rpc
        .pause_tree(&backend.authority, &backend.tree, false)
        .expect("unpause tree");
    backend
        .rpc
        .deposit_sol(&tree, &depositor, 1_000_000, [1; 32], [2; 31])
        .expect("deposit after unpause");
    assert_ne!(backend.rpc.state_root(&tree), Some(root));
}
