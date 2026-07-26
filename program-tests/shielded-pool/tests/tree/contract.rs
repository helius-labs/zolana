use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::error::ShieldedPoolError;
use zolana_program_test::Rejection;
use zolana_test_utils::backend::LiteSvmPoolBackend;
use zolana_tree::{INITIALIZED, PAUSED};

/// TreeAccountLayout: discriminator at byte 0, state at byte 1.
fn tree_state_byte(backend: &LiteSvmPoolBackend, tree: &Pubkey) -> u8 {
    backend
        .rpc
        .account_data(tree)
        .expect("tree account")
        .get(1)
        .copied()
        .expect("tree state byte")
}

#[test]
fn pause_blocks_tree_mutation_and_unpause_restores_it() {
    let mut backend = LiteSvmPoolBackend::initialized();
    let depositor = backend.funded_signer(2_000_000_000);
    let tree = backend.tree.pubkey();
    assert_eq!(tree_state_byte(&backend, &tree), INITIALIZED);

    backend
        .rpc
        .pause_tree(&backend.authority, &backend.tree, true)
        .expect("pause tree");
    assert_eq!(tree_state_byte(&backend, &tree), PAUSED);
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
    assert_eq!(tree_state_byte(&backend, &tree), INITIALIZED);
    backend
        .rpc
        .deposit_sol(&tree, &depositor, 1_000_000, [1; 32], [2; 31])
        .expect("deposit after unpause");
    assert_ne!(backend.rpc.state_root(&tree), Some(root));
}
