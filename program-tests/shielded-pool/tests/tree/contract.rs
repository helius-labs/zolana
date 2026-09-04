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
    let tree = backend.tree;
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
    let tree = backend.tree;

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

mod program_unit {
    use pinocchio::error::ProgramError;
    use shielded_pool_program::{
        testing::{check_reimbursement_recipient, pay_reimbursement_with_rent_minimum, tree_error},
        ID,
    };
    use zolana_account_checks::account_info::test_account_info::get_account_view;
    use zolana_interface::error::ShieldedPoolError;

    #[test]
    fn reimbursement_recipient_must_not_be_program_owned() {
        let program_owned =
            get_account_view([3; 32], ID.to_bytes(), false, true, false, vec![0; 10]);
        assert_eq!(
            check_reimbursement_recipient(&program_owned),
            Err(ProgramError::Custom(
                ShieldedPoolError::InvalidReimbursementRecipient as u32
            ))
        );

        let system_owned = get_account_view([4; 32], [0; 32], false, true, false, vec![]);
        assert_eq!(check_reimbursement_recipient(&system_owned), Ok(()));
        let other_program = get_account_view([5; 32], [9; 32], false, true, false, vec![1; 8]);
        assert_eq!(check_reimbursement_recipient(&other_program), Ok(()));
    }

    #[test]
    fn reimbursement_moves_funded_lamports_and_preserves_rent() {
        let mut tree = get_account_view([1; 32], ID.to_bytes(), false, true, false, vec![0; 10]);
        let mut recipient = get_account_view([2; 32], [0; 32], false, true, false, vec![]);
        tree.set_lamports(6_500);
        recipient.set_lamports(1_000);

        pay_reimbursement_with_rent_minimum(&mut tree, &mut recipient, 5_000, 1_500).unwrap();

        assert_eq!(tree.lamports(), 1_500);
        assert_eq!(recipient.lamports(), 6_000);
    }

    #[test]
    fn reimbursement_cannot_spend_tree_rent() {
        let mut tree = get_account_view([1; 32], ID.to_bytes(), false, true, false, vec![0; 10]);
        let mut recipient = get_account_view([2; 32], [0; 32], false, true, false, vec![]);
        tree.set_lamports(6_499);

        let error = pay_reimbursement_with_rent_minimum(&mut tree, &mut recipient, 5_000, 1_500)
            .unwrap_err();

        assert_eq!(
            error,
            ProgramError::Custom(ShieldedPoolError::InsufficientForesterFeeBalance as u32)
        );
        assert_eq!(tree.lamports(), 6_499);
        assert_eq!(recipient.lamports(), 1_000);
    }

    /// 7026 leg: recipient.lamports() + amount overflows u64.
    #[test]
    fn reimbursement_recipient_balance_overflow_is_invalid_forester_fee() {
        let mut tree = get_account_view([1; 32], ID.to_bytes(), false, true, false, vec![0; 10]);
        let mut recipient = get_account_view([2; 32], [0; 32], false, true, false, vec![]);
        tree.set_lamports(10_000_000);
        recipient.set_lamports(u64::MAX - 100);

        let error = pay_reimbursement_with_rent_minimum(&mut tree, &mut recipient, 5_000, 1_500)
            .unwrap_err();

        assert_eq!(
            error,
            ProgramError::Custom(ShieldedPoolError::InvalidForesterFee as u32)
        );
        // The failed add must not move any lamports.
        assert_eq!(tree.lamports(), 10_000_000);
        assert_eq!(recipient.lamports(), u64::MAX - 100);
    }

    /// The program-side `tree_error` conversion table (INV-XC-31): Paused,
    /// InvalidRootIndex, TreeIsFull, and FeeOverflow have named mappings; every
    /// other variant hits the catch-all.
    #[test]
    fn tree_error_table_is_stable() {
        use zolana_tree::TreeError;

        let named = [
            (TreeError::Paused, ShieldedPoolError::TreePaused as u32),
            (
                TreeError::FeeOverflow,
                ShieldedPoolError::InvalidForesterFee as u32,
            ),
            (
                TreeError::InvalidRootIndex,
                ShieldedPoolError::StaleNullifierRoot as u32,
            ),
            (
                TreeError::TreeIsFull,
                ShieldedPoolError::StateAppendFailed as u32,
            ),
        ];
        for (variant, want) in named {
            assert_eq!(
                tree_error(variant),
                ProgramError::Custom(want),
                "{variant:?}"
            );
        }

        let catch_all = [
            TreeError::InvalidBufferSize,
            TreeError::HeightTooLarge,
            TreeError::Deserialize,
            TreeError::NullifierInit,
            TreeError::AlreadyInitialized,
            TreeError::InvalidOwner,
            TreeError::NotWritable,
            TreeError::InvalidDiscriminator,
            TreeError::Borrowed,
            TreeError::InvalidCapacity,
            TreeError::Hash,
        ];
        for variant in catch_all {
            assert_eq!(
                tree_error(variant),
                ProgramError::Custom(ShieldedPoolError::InvalidTreeAccounts as u32),
                "{variant:?} must hit the catch-all"
            );
        }
    }
}
