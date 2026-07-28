use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::error::ShieldedPoolError;
use zolana_program_test::Rejection;
use zolana_test_utils::backend::LiteSvmPoolBackend;
use zolana_tree::{TreeAccount, INITIALIZED, PAUSED};

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
        .deposit_sol(&tree, &depositor, 1_000_000, [1; 32], [2; 32])
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
        .deposit_sol(&tree, &depositor, 1_000_000, [1; 32], [2; 32])
        .expect("deposit after unpause");
    assert_ne!(backend.rpc.state_root(&tree), Some(root));
}

#[test]
fn deposit_rejects_an_append_to_a_full_utxo_tree() {
    let mut backend = LiteSvmPoolBackend::initialized();
    let depositor = backend.funded_signer(2_000_000_000);
    let tree = backend.tree.pubkey();

    // Drive the UTXO tree to capacity by moving its cursor; the next append
    // must fail `TreeError::TreeIsFull`, which the shared `tree_error` mapping
    // reports as StateAppendFailed (7004).
    let mut account = backend.rpc.svm.get_account(&tree).expect("tree account");
    {
        let mut on_chain =
            TreeAccount::from_bytes(&mut account.data, tree.to_bytes()).expect("load tree");
        let capacity = on_chain.utxo_tree().capacity();
        on_chain.utxo_tree().next_index = capacity.to_le_bytes();
    }
    backend
        .rpc
        .svm
        .set_account(tree, account)
        .expect("write full tree account");

    let error = backend
        .rpc
        .deposit_sol(&tree, &depositor, 1_000_000, [1; 32], [2; 32])
        .expect_err("an append to a full tree must fail");
    Rejection::pool(ShieldedPoolError::StateAppendFailed).assert_litesvm(error);
    backend
        .rpc
        .last_transaction_trace()
        .expect("full-tree transaction trace")
        .assert_rolled_back_except(&[backend.rpc.payer.pubkey()]);
}
