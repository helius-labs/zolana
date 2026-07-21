use mollusk_solana_account::Account as MolluskAccount;
use mollusk_solana_instruction::AccountMeta as MolluskAccountMeta;
use mollusk_solana_program_error::ProgramError;
use mollusk_solana_pubkey::Pubkey as MolluskPubkey;
use solana_instruction::{error::InstructionError, AccountMeta};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_account_checks::AccountError;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{tag, ZoneDeposit},
    pda,
};
use zolana_program_test::{ZolanaProgramTest, ZONE_TEST_PROGRAM_ID};
use zolana_test_utils::litesvm_asserts::{assert_instruction_error, assert_pool_error};

use zolana_mollusk_harness::{
    assert_rejected_atomically, expect_err_atomic, mollusk_pubkey, sweep_account_matrix,
    AccountMutation, Expected,
};

use crate::{
    mollusk::deposit_fixture,
    support::{raw_sol_deposit, sol_deposit_accounts, Pool},
};

#[test]
fn sol_deposit_rejects_zero_amount() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(1_000_000_000);
    let tree = pool.tree.pubkey();
    let data = ZolanaProgramTest::sol_shield_data(0, [2u8; 32], [2u8; 31]);

    let err = pool
        .rpc
        .deposit(&tree, &depositor, &data)
        .expect_err("invalid amount must fail");
    assert_pool_error(err, ShieldedPoolError::InvalidTransactShape);
}

#[test]
fn spl_deposit_rejects_zero_amount_before_account_loading() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(1_000_000_000);
    let tree = pool.tree.pubkey();
    let zero_spl = ZolanaProgramTest::spl_shield_data(0, [3u8; 32], [3u8; 31]);
    let bogus_token_account = pool.rpc.payer.pubkey();
    let bogus_mint = pool.rpc.payer.pubkey();

    let err = pool
        .rpc
        .deposit_spl(
            &tree,
            &depositor,
            &bogus_token_account,
            &bogus_mint,
            &zero_spl,
        )
        .expect_err("zero SPL amount must fail before account loading");
    assert_pool_error(err, ShieldedPoolError::InvalidTransactShape);
}

#[test]
fn sol_deposit_rejects_missing_program_account() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(2_000_000_000);
    let tree = pool.tree.pubkey();
    let mut missing_program = sol_deposit_accounts(&pool.rpc, tree, depositor.pubkey());
    missing_program.pop();

    let err = raw_sol_deposit(&mut pool.rpc, &depositor, missing_program)
        .expect_err("missing program account must fail");
    assert_instruction_error(
        err,
        InstructionError::Custom(u32::from(AccountError::NotEnoughAccountKeys)),
    );
}

#[test]
fn sol_deposit_rejects_wrong_vault() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(2_000_000_000);
    let tree = pool.tree.pubkey();
    let mut wrong_vault = sol_deposit_accounts(&pool.rpc, tree, depositor.pubkey());
    *wrong_vault.get_mut(3).expect("vault account") =
        AccountMeta::new(pool.rpc.payer.pubkey(), false);

    let err =
        raw_sol_deposit(&mut pool.rpc, &depositor, wrong_vault).expect_err("wrong vault must fail");
    assert_pool_error(err, ShieldedPoolError::InvalidSettlementAccounts);
}

#[test]
fn sol_deposit_rejects_extra_settlement_account() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(2_000_000_000);
    let tree = pool.tree.pubkey();
    let mut extra = sol_deposit_accounts(&pool.rpc, tree, depositor.pubkey());
    extra.insert(5, AccountMeta::new_readonly(pool.rpc.payer.pubkey(), false));

    let err = raw_sol_deposit(&mut pool.rpc, &depositor, extra)
        .expect_err("extra settlement account must fail");
    assert_pool_error(err, ShieldedPoolError::InvalidSettlementAccounts);
}

#[test]
fn sol_deposit_rejects_foreign_source() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(2_000_000_000);
    let tree = pool.tree.pubkey();
    let mut foreign_source = sol_deposit_accounts(&pool.rpc, tree, depositor.pubkey());
    *foreign_source.get_mut(4).expect("source account") =
        AccountMeta::new(pool.rpc.payer.pubkey(), false);

    let err = raw_sol_deposit(&mut pool.rpc, &depositor, foreign_source)
        .expect_err("foreign source must fail");
    assert_pool_error(err, ShieldedPoolError::InvalidSettlementAccounts);
}

#[test]
fn sol_deposit_rejects_foreign_tree_atomically() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(2_000_000_000);
    let tree = pool.tree.pubkey();
    let tree_before = pool.rpc.account_data(&tree).expect("tree");
    let depositor_before = pool
        .rpc
        .svm
        .get_account(&depositor.pubkey())
        .expect("depositor")
        .lamports;
    let mut foreign_tree = sol_deposit_accounts(&pool.rpc, tree, depositor.pubkey());
    *foreign_tree.first_mut().expect("tree account") =
        AccountMeta::new(pda::protocol_config(), false);

    let err = raw_sol_deposit(&mut pool.rpc, &depositor, foreign_tree)
        .expect_err("foreign tree must fail");
    assert_pool_error(err, ShieldedPoolError::InvalidTreeAccounts);
    assert_eq!(pool.rpc.account_data(&tree), Some(tree_before));
    assert_eq!(
        pool.rpc
            .svm
            .get_account(&depositor.pubkey())
            .expect("depositor")
            .lamports,
        depositor_before
    );
}

#[test]
fn paused_tree_rejects_sol_deposit() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(2_000_000_000);
    let tree = pool.tree.pubkey();
    pool.rpc
        .pause_tree(&pool.authority, &pool.tree, true)
        .expect("pause tree");

    let err = pool
        .rpc
        .deposit_sol(&tree, &depositor, 1_000_000, [4u8; 32], [4u8; 31])
        .expect_err("paused tree deposit must fail");
    assert_pool_error(err, ShieldedPoolError::TreePaused);
}

#[test]
fn zone_deposit_rejects_a_signer_that_is_not_the_zone_authority() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(5_000_000_000);
    let tree = pool.tree.pubkey();
    let data = pool
        .rpc
        .zone_sol_shield_data(1_000_000, [3u8; 32], [4u8; 31]);
    let mut ix = ZoneDeposit {
        tree,
        depositor: depositor.pubkey(),
        spl: None,
        view_tag: data.view_tag,
        owner: data.owner,
        blinding: data.blinding,
        amount: data.amount,
        zone_program_id: Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID),
        zone_data_hash: data.zone_data_hash,
        zone_data: data.zone_data,
        utxo_data: data.utxo_data,
        memo: None,
    }
    .cpi_instruction();
    ix.accounts
        .get_mut(2)
        .expect("zone authority account")
        .pubkey = depositor.pubkey();

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&depositor])
        .expect_err("wrong zone signer must fail");
    assert_pool_error(err, ShieldedPoolError::InvalidZoneConfig);
}

#[test]
fn mollusk_deposit_rejects_truncated_data_exactly_and_atomically() {
    let (mollusk, valid, accounts) = deposit_fixture();
    let mut truncated = valid;
    truncated.data = vec![tag::DEPOSIT, 1, 2, 3];

    expect_err_atomic(
        &mollusk,
        &truncated,
        &accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidInstructionData as u32),
    );
}

#[test]
fn mollusk_deposit_rejects_every_account_privilege_downgrade() {
    let (mollusk, valid, accounts) = deposit_fixture();
    // Metas: [0] tree, [1] depositor (signer), [2] system-program
    // placeholder, [3] SOL vault, [4] depositor settlement handle, [5]
    // shielded-pool program. Positions 1 and 4 are duplicate metas of one
    // account, and the runtime takes the union of duplicate-meta privileges,
    // so downgrading the writable flag on either one alone must keep
    // succeeding. The signer and trailing-account cells have stable errors;
    // the remaining downgrades shift the account shape, so only
    // deterministic atomic rejection is pinned.
    let program_index = valid.accounts.len().saturating_sub(1);
    sweep_account_matrix(&mollusk, &valid, &accounts, |mutation| match mutation {
        AccountMutation::Unsign { index: 1 } => {
            Expected::Err(ProgramError::MissingRequiredSignature)
        }
        AccountMutation::Readonly { index: 1 | 4 } => Expected::Success,
        AccountMutation::Remove { index } if index == program_index => Expected::Err(
            ProgramError::Custom(u32::from(AccountError::NotEnoughAccountKeys)),
        ),
        _ => Expected::Rejected,
    });
}

#[test]
fn mollusk_deposit_rejects_wrong_program_account_exactly_and_atomically() {
    let (mollusk, valid, accounts) = deposit_fixture();
    let wrong_program = Pubkey::new_unique();
    let mut wrong_program_ix = valid;
    *wrong_program_ix
        .accounts
        .last_mut()
        .expect("program account") = MolluskAccountMeta {
        pubkey: mollusk_pubkey(&wrong_program),
        is_signer: false,
        is_writable: false,
    };
    let mut wrong_program_accounts = accounts;
    *wrong_program_accounts.last_mut().expect("program account") = (
        mollusk_pubkey(&wrong_program),
        MolluskAccount {
            lamports: 1,
            data: Vec::new(),
            owner: MolluskPubkey::new_from_array([0u8; 32]),
            executable: false,
            rent_epoch: 0,
        },
    );

    expect_err_atomic(
        &mollusk,
        &wrong_program_ix,
        &wrong_program_accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidSettlementAccounts as u32),
    );
}

#[test]
fn mollusk_deposit_rejects_reordered_accounts_atomically() {
    let (mollusk, mut valid, accounts) = deposit_fixture();
    valid.accounts.swap(0, 1);
    assert_rejected_atomically(&mollusk, &valid, &accounts);
}

#[test]
fn mollusk_deposit_rejects_wrong_tree_owner_atomically() {
    let (mollusk, valid, mut accounts) = deposit_fixture();
    accounts.first_mut().expect("tree account").1.owner = MolluskPubkey::new_from_array([0x55; 32]);
    assert_rejected_atomically(&mollusk, &valid, &accounts);
}

#[test]
fn mollusk_deposit_rejects_truncated_tree_atomically() {
    let (mollusk, valid, mut accounts) = deposit_fixture();
    accounts
        .first_mut()
        .expect("tree account")
        .1
        .data
        .truncate(1);
    assert_rejected_atomically(&mollusk, &valid, &accounts);
}

#[test]
fn mollusk_deposit_rejects_unfunded_depositor_atomically() {
    let (mollusk, valid, mut accounts) = deposit_fixture();
    accounts.get_mut(1).expect("depositor account").1.lamports = 0;
    assert_rejected_atomically(&mollusk, &valid, &accounts);
}
