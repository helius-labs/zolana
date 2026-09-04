use mollusk_svm::result::Check;
use solana_keypair::Keypair;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_account_checks::AccountError;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{SetTreeFees, UpdateProtocolConfigData},
    state::{default_tree_fees, TreeFeeSchedule},
};
use zolana_program_test::Rejection;
use zolana_test_utils::mollusk::{
    expect_err_exact, mollusk_pubkey, sweep_account_matrix, AccountMutation, Expected,
};
use zolana_test_utils::nullifier_pda::tree_fees;
use zolana_tree::{TreeAccountLayout, PAUSED, UTXO_TREE_HEIGHT};

type Layout = TreeAccountLayout<
    UTXO_TREE_HEIGHT,
    { zolana_tree::nullifier_tree::constants::NULLIFIER_TREE_ZKP_BATCHES },
>;

use shielded_pool_tests::support::{
    fixtures::Pool,
    mollusk::{
        account_named, set_tree_fees_fixture, system_account, SET_TREE_FEES_FIXTURE_SCHEDULE,
    },
};

fn set_fees_ix(
    pool: &Pool,
    authority: &Keypair,
    fees: TreeFeeSchedule,
) -> solana_instruction::Instruction {
    SetTreeFees {
        authority: authority.pubkey(),
        tree: pool.tree,
        fees,
    }
    .instruction()
}

#[test]
fn set_tree_fees_changes_only_the_schedule_bytes() {
    let (mollusk, instruction, accounts) = set_tree_fees_fixture();
    let result =
        mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);

    let authority = instruction.accounts.first().expect("authority meta").pubkey;
    let config = instruction.accounts.get(1).expect("config meta").pubkey;
    let tree = instruction.accounts.get(2).expect("tree meta").pubkey;

    for key in [authority, config] {
        assert_eq!(
            account_named(&result.resulting_accounts, &key),
            account_named(&accounts, &key),
            "set_tree_fees must not change account {key}"
        );
    }

    let tree_before = account_named(&accounts, &tree);
    let tree_after = account_named(&result.resulting_accounts, &tree);
    let mut expected = tree_before.clone();
    {
        let layout: &mut Layout =
            wincode::deserialize_mut(&mut expected.data).expect("tree layout");
        assert_ne!(layout.fees, SET_TREE_FEES_FIXTURE_SCHEDULE);
        assert_eq!(layout.fee_balance, 0);
        layout.fees = SET_TREE_FEES_FIXTURE_SCHEDULE;
    }
    assert_eq!(
        tree_after, &expected,
        "set_tree_fees must change only the schedule bytes"
    );
}

#[test]
fn set_tree_fees_works_on_a_paused_tree_and_keeps_the_fee_balance() {
    let mut pool = Pool::initialized();
    let authority = pool.authority.insecure_clone();
    let tree = pool.tree;
    let mut account = pool.rpc.svm.get_account(&tree).expect("tree");
    {
        let layout: &mut Layout = wincode::deserialize_mut(&mut account.data).expect("tree layout");
        layout.fee_balance = 777;
    }
    account.lamports += 777;
    pool.rpc
        .svm
        .set_account(tree, account)
        .expect("write fee balance");
    pool.rpc
        .pause_tree(&authority, &tree, true)
        .expect("pause tree");

    pool.rpc
        .set_tree_fees(&authority, &tree, SET_TREE_FEES_FIXTURE_SCHEDULE)
        .expect("set fees on a paused tree");

    assert_eq!(
        tree_fees(&pool.rpc, &tree).expect("tree fees"),
        (SET_TREE_FEES_FIXTURE_SCHEDULE, 777)
    );
    assert_eq!(
        pool.rpc.account_data(&tree).expect("tree").get(1),
        Some(&PAUSED),
        "set_tree_fees leaves the pause state alone"
    );
}

#[test]
fn set_tree_fees_is_gated_by_the_fee_authority_alone() {
    let mut pool = Pool::initialized();
    let protocol_authority = pool.authority.insecure_clone();
    let fee_authority = Keypair::new();
    pool.rpc
        .airdrop(&fee_authority.pubkey(), 1_000_000_000)
        .expect("fund fee authority");
    pool.rpc
        .send_protocol_config_update(
            &protocol_authority,
            UpdateProtocolConfigData::FeeAuthority(fee_authority.pubkey()),
        )
        .expect("rotate fee authority");
    let before = tree_fees(&pool.rpc, &pool.tree).expect("tree fees");

    let error = pool
        .rpc
        .create_and_send_default_payer_transaction(
            &[set_fees_ix(
                &pool,
                &protocol_authority,
                SET_TREE_FEES_FIXTURE_SCHEDULE,
            )],
            &[&protocol_authority],
        )
        .expect_err("the protocol authority is no longer the fee authority");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(error);
    pool.rpc
        .last_transaction_trace()
        .expect("rejected trace")
        .assert_rolled_back_except(&[pool.rpc.payer.pubkey()]);
    assert_eq!(tree_fees(&pool.rpc, &pool.tree).expect("tree fees"), before);

    pool.rpc
        .set_tree_fees(&fee_authority, &pool.tree, SET_TREE_FEES_FIXTURE_SCHEDULE)
        .expect("the fee authority sets the schedule");
    assert_eq!(
        tree_fees(&pool.rpc, &pool.tree).expect("tree fees"),
        (SET_TREE_FEES_FIXTURE_SCHEDULE, 0)
    );
}

#[test]
fn set_tree_fees_stores_insolvent_schedules() {
    let mut pool = Pool::initialized();
    let authority = pool.authority.insecure_clone();
    let valid = default_tree_fees(250).expect("default tree fees");
    let insolvent = [
        TreeFeeSchedule {
            append_reimbursement: valid.append_reimbursement + 1,
            ..valid
        },
        TreeFeeSchedule {
            close_reimbursement: valid.close_reimbursement + 1,
            ..valid
        },
        TreeFeeSchedule {
            fee_per_nullifier: valid.fee_per_nullifier - 1,
            ..valid
        },
    ];
    for fees in insolvent {
        pool.rpc
            .create_and_send_default_payer_transaction(
                &[set_fees_ix(&pool, &authority, fees)],
                &[&authority],
            )
            .expect("an insolvent schedule is stored as submitted");
        assert_eq!(
            tree_fees(&pool.rpc, &pool.tree).expect("tree fees"),
            (fees, 0),
            "{fees:?}"
        );
    }
}

#[test]
fn mollusk_set_tree_fees_rejects_every_account_privilege_downgrade() {
    let (mollusk, valid, accounts) = set_tree_fees_fixture();
    sweep_account_matrix(&mollusk, &valid, &accounts, |mutation| match mutation {
        AccountMutation::Unsign { index: 0 } => {
            Expected::Err(ProgramError::Custom(u32::from(AccountError::InvalidSigner)))
        }
        AccountMutation::Readonly { index: 2 } => Expected::Err(ProgramError::Custom(u32::from(
            AccountError::AccountNotMutable,
        ))),
        _ => Expected::Rejected,
    });
}

#[test]
fn set_tree_fees_rejects_wrong_authority_exactly() {
    let (mollusk, valid, accounts) = set_tree_fees_fixture();
    let wrong_authority = Pubkey::new_unique();
    let mut wrong_authority_ix = valid;
    wrong_authority_ix
        .accounts
        .first_mut()
        .expect("authority meta")
        .pubkey = mollusk_pubkey(&wrong_authority);
    let mut wrong_authority_accounts = accounts;
    *wrong_authority_accounts
        .first_mut()
        .expect("authority account") = (
        mollusk_pubkey(&wrong_authority),
        system_account(1_000_000_000),
    );

    expect_err_exact(
        &mollusk,
        &wrong_authority_ix,
        &wrong_authority_accounts,
        ProgramError::Custom(ShieldedPoolError::UnauthorizedCaller as u32),
    );
}

#[test]
fn set_tree_fees_rejects_a_payload_that_is_not_exactly_the_schedule() {
    let (mollusk, valid, accounts) = set_tree_fees_fixture();
    assert_eq!(valid.data.len(), 25);

    let mut short_payload = valid.clone();
    short_payload.data.truncate(24);
    expect_err_exact(
        &mollusk,
        &short_payload,
        &accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidInstructionData as u32),
    );

    let mut long_payload = valid;
    long_payload.data.push(0);
    expect_err_exact(
        &mollusk,
        &long_payload,
        &accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidInstructionData as u32),
    );
}

#[test]
fn set_tree_fees_rejects_a_non_tree_account() {
    let (mollusk, valid, accounts) = set_tree_fees_fixture();
    let impostor = Pubkey::new_unique();
    let mut impostor_ix = valid;
    impostor_ix.accounts.get_mut(2).expect("tree meta").pubkey = mollusk_pubkey(&impostor);
    let mut impostor_accounts = accounts;
    *impostor_accounts.get_mut(2).expect("tree account") =
        (mollusk_pubkey(&impostor), system_account(1_000_000));

    expect_err_exact(
        &mollusk,
        &impostor_ix,
        &impostor_accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidTreeAccounts as u32),
    );
}

#[test]
fn set_tree_fees_rejects_a_non_config_account() {
    let (mollusk, valid, accounts) = set_tree_fees_fixture();
    let impostor = Pubkey::new_unique();
    let mut impostor_ix = valid;
    impostor_ix.accounts.get_mut(1).expect("config meta").pubkey = mollusk_pubkey(&impostor);
    let mut impostor_accounts = accounts;
    *impostor_accounts.get_mut(1).expect("config account") =
        (mollusk_pubkey(&impostor), system_account(1_000_000));

    expect_err_exact(
        &mollusk,
        &impostor_ix,
        &impostor_accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidProtocolConfig as u32),
    );
}
