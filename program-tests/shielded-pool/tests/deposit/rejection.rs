use solana_account::Account as MolluskAccount;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_system_interface::error::SystemError;
use zolana_account_checks::AccountError;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        tag, AssetDeposit, DepositAsset, DepositAssetKind, DepositEntry, ZoneAssetDeposit,
        ZoneDeposit,
    },
    pda, PROGRAM_ID_PUBKEY,
};
use zolana_program_test::{test_blinding, Rejection, ZolanaProgramTest, ZONE_TEST_PROGRAM_ID};

use zolana_test_utils::mollusk::{
    expect_err_exact, mollusk_pubkey, snapshot_instruction_accounts, sweep_account_matrix,
    AccountMutation, Expected,
};

use shielded_pool_tests::support::{
    fixtures::{
        raw_deposit_batch, raw_sol_deposit, register_mint, sol_deposit_accounts,
        sol_group_accounts, spl_depositor, spl_group_accounts, Pool,
    },
    mollusk::{deposit_fixture, setup_mollusk},
};

#[test]
fn sol_deposit_accepts_zero_amount() {
    // PR164 dropped the zero-amount deposit gate: a zero-value entry settles
    // nothing and appends an empty proofless output.
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(1_000_000_000);
    let tree = pool.tree.pubkey();
    let data = ZolanaProgramTest::sol_shield_data(0, [2u8; 32], [2u8; 32]);

    let event = pool
        .rpc
        .deposit(&tree, &depositor, &data)
        .expect("zero-amount deposit is accepted");
    assert_eq!(event.output.amount, 0);
}

#[test]
fn spl_deposit_accepts_zero_amount() {
    // PR164 dropped the zero-amount gate; the SPL leg is a zero-value token
    // transfer, so the token accounts must still exist and match the mint.
    let mut pool = Pool::initialized();
    let (mint, _, vault) = register_mint(&mut pool);
    let (depositor, user_token) = spl_depositor(&mut pool, mint, 1_000);
    let tree = pool.tree.pubkey();
    let zero_spl = ZolanaProgramTest::spl_shield_data(0, [3u8; 32], [3u8; 32], &mint, &user_token);

    let event = pool
        .rpc
        .deposit(&tree, &depositor, &zero_spl)
        .expect("zero-amount SPL deposit is accepted");
    assert_eq!(event.output.amount, 0);
    assert_eq!(pool.rpc.token_balance(&user_token), Some(1_000));
    assert_eq!(pool.rpc.token_balance(&vault), Some(0));
}

/// Raw batch entry with placeholder output fields, for tests that violate an
/// instruction-data invariant the `Deposit` builder never produces.
fn raw_entry(amount: u64) -> DepositEntry {
    DepositEntry {
        asset_index: 0,
        view_tag: [9u8; 32],
        owner: [9u8; 32],
        blinding: test_blinding(9),
        amount,
        utxo_data: None,
        memo: None,
    }
}

fn spl_asset_kind(mint: &Pubkey) -> DepositAssetKind {
    DepositAssetKind::Spl {
        vault_bump: pda::spl_asset_vault_with_bump(mint).1,
    }
}

#[test]
fn deposit_batch_rejects_an_empty_batch() {
    // The builder refuses empty batches (`DepositBuildError::EmptyBatch`), so
    // only raw instruction data can reach this on-chain check.
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(5_000_000_000);
    let tree = pool.tree.pubkey();

    let err = raw_deposit_batch(
        &mut pool.rpc,
        tree,
        &depositor,
        vec![DepositAssetKind::Sol],
        Vec::new(),
        vec![sol_group_accounts()],
    )
    .expect_err("empty batch must fail");
    Rejection::pool(ShieldedPoolError::EmptyDepositBatch).assert_litesvm(err);
}

#[test]
fn deposit_batch_rejects_an_out_of_range_asset_index() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(5_000_000_000);
    let tree = pool.tree.pubkey();
    let mut entry = raw_entry(1_000);
    entry.asset_index = 1;

    let err = raw_deposit_batch(
        &mut pool.rpc,
        tree,
        &depositor,
        vec![DepositAssetKind::Sol],
        vec![entry],
        vec![sol_group_accounts()],
    )
    .expect_err("out-of-range asset index must fail");
    Rejection::pool(ShieldedPoolError::InvalidDepositAssetIndex).assert_litesvm(err);
}

#[test]
fn deposit_batch_rejects_summed_amounts_that_overflow() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(5_000_000_000);
    let tree = pool.tree.pubkey();

    let err = raw_deposit_batch(
        &mut pool.rpc,
        tree,
        &depositor,
        vec![DepositAssetKind::Sol],
        vec![raw_entry(u64::MAX), raw_entry(1)],
        vec![sol_group_accounts()],
    )
    .expect_err("overflowing summed amounts must fail");
    Rejection::pool(ShieldedPoolError::DepositAmountOverflow).assert_litesvm(err);
}

#[test]
fn deposit_batch_rejects_a_declared_asset_no_entry_funds() {
    let mut pool = Pool::initialized();
    let (mint, _, _) = register_mint(&mut pool);
    let (depositor, user_token) = spl_depositor(&mut pool, mint, 1_000_000);
    let tree = pool.tree.pubkey();

    let err = raw_deposit_batch(
        &mut pool.rpc,
        tree,
        &depositor,
        vec![DepositAssetKind::Sol, spl_asset_kind(&mint)],
        vec![raw_entry(1_000)],
        vec![sol_group_accounts(), spl_group_accounts(mint, user_token)],
    )
    .expect_err("unfunded declared asset must fail");
    Rejection::pool(ShieldedPoolError::UnreferencedDepositAsset).assert_litesvm(err);
}

#[test]
fn deposit_batch_rejects_declaring_the_same_mint_twice() {
    let mut pool = Pool::initialized();
    let (mint, _, _) = register_mint(&mut pool);
    let (depositor, user_token) = spl_depositor(&mut pool, mint, 1_000_000);
    let tree = pool.tree.pubkey();
    let mut second = raw_entry(1_000);
    second.asset_index = 1;

    let err = raw_deposit_batch(
        &mut pool.rpc,
        tree,
        &depositor,
        vec![spl_asset_kind(&mint), spl_asset_kind(&mint)],
        vec![raw_entry(1_000), second],
        vec![
            spl_group_accounts(mint, user_token),
            spl_group_accounts(mint, user_token),
        ],
    )
    .expect_err("duplicate mint must fail");
    Rejection::pool(ShieldedPoolError::DuplicateDepositAsset).assert_litesvm(err);
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
    Rejection::custom(u32::from(AccountError::NotEnoughAccountKeys)).assert_litesvm(err);
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
    Rejection::pool(ShieldedPoolError::InvalidSettlementAccounts).assert_litesvm(err);
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
    Rejection::pool(ShieldedPoolError::InvalidSettlementAccounts).assert_litesvm(err);
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
    Rejection::pool(ShieldedPoolError::InvalidSettlementAccounts).assert_litesvm(err);
}

#[test]
fn sol_deposit_rejects_wrong_system_program_account() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(2_000_000_000);
    let tree = pool.tree.pubkey();
    let mut wrong_system = sol_deposit_accounts(&pool.rpc, tree, depositor.pubkey());
    *wrong_system.get_mut(2).expect("system program account") =
        AccountMeta::new_readonly(Pubkey::new_unique(), false);

    let err = raw_sol_deposit(&mut pool.rpc, &depositor, wrong_system)
        .expect_err("wrong system program account must fail");
    Rejection::pool(ShieldedPoolError::InvalidSettlementAccounts).assert_litesvm(err);
}

#[test]
fn sol_deposit_rejects_readonly_sol_interface() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(2_000_000_000);
    let tree = pool.tree.pubkey();
    let mut readonly_interface = sol_deposit_accounts(&pool.rpc, tree, depositor.pubkey());
    *readonly_interface.get_mut(3).expect("vault account") =
        AccountMeta::new_readonly(pda::sol_interface(), false);

    let err = raw_sol_deposit(&mut pool.rpc, &depositor, readonly_interface)
        .expect_err("read-only sol_interface must fail");
    Rejection::pool(ShieldedPoolError::InvalidSettlementAccounts).assert_litesvm(err);
}

#[test]
fn sol_deposit_rejects_readonly_user_sol() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(2_000_000_000);
    let tree = pool.tree.pubkey();
    // Positions 1 and 4 are duplicate metas of the depositor and the runtime
    // takes the union of duplicate-meta privileges, so both must be downgraded
    // for the account to actually be read-only.
    let mut readonly_user = sol_deposit_accounts(&pool.rpc, tree, depositor.pubkey());
    *readonly_user.get_mut(1).expect("depositor account") =
        AccountMeta::new_readonly(depositor.pubkey(), true);
    *readonly_user.get_mut(4).expect("source account") =
        AccountMeta::new_readonly(depositor.pubkey(), false);

    let err = raw_sol_deposit(&mut pool.rpc, &depositor, readonly_user)
        .expect_err("read-only user_sol must fail");
    Rejection::pool(ShieldedPoolError::InvalidSettlementAccounts).assert_litesvm(err);
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
    Rejection::pool(ShieldedPoolError::InvalidTreeAccounts).assert_litesvm(err);
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
        .deposit_sol(&tree, &depositor, 1_000_000, [4u8; 32], [4u8; 32])
        .expect_err("paused tree deposit must fail");
    Rejection::pool(ShieldedPoolError::TreePaused).assert_litesvm(err);
}

#[test]
fn paused_tree_rejects_zone_deposit() {
    let mut pool = Pool::initialized();
    pool.rpc
        .load_zone_test_program()
        .expect("load zone test program");
    let zone_authority = pool.authority.insecure_clone();
    pool.rpc
        .create_zone_config(&zone_authority, &zone_authority.pubkey(), true)
        .expect("create zone config");
    let depositor = pool.funded_signer(2_000_000_000);
    let tree = pool.tree.pubkey();
    pool.rpc
        .pause_tree(&pool.authority, &pool.tree, true)
        .expect("pause tree");
    let data = pool
        .rpc
        .zone_sol_shield_data(1_000_000, [4u8; 32], [4u8; 32]);

    let err = pool
        .rpc
        .zone_deposit(&tree, &depositor, &data)
        .expect_err("paused tree zone deposit must fail");
    Rejection::pool(ShieldedPoolError::TreePaused).assert_litesvm(err);
}

#[test]
fn zone_deposit_rejects_a_signer_that_is_not_the_zone_authority() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(5_000_000_000);
    let tree = pool.tree.pubkey();
    let data = pool
        .rpc
        .zone_sol_shield_data(1_000_000, [3u8; 32], [4u8; 32]);
    let mut ix = ZoneDeposit {
        tree,
        depositor: depositor.pubkey(),
        zone_program_id: Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID),
        deposits: vec![data],
    }
    .cpi_instruction()
    .expect("zone deposit instruction");
    ix.accounts
        .get_mut(2)
        .expect("zone authority account")
        .pubkey = depositor.pubkey();

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&depositor])
        .expect_err("wrong zone signer must fail");
    Rejection::pool(ShieldedPoolError::InvalidZoneConfig).assert_litesvm(err);
}

#[test]
fn zone_deposit_rejects_an_unsigned_zone_config() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(5_000_000_000);
    let tree = pool.tree.pubkey();
    let data = pool
        .rpc
        .zone_sol_shield_data(1_000_000, [3u8; 32], [4u8; 32]);
    let mut ix = ZoneDeposit {
        tree,
        depositor: depositor.pubkey(),
        zone_program_id: Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID),
        deposits: vec![data],
    }
    .cpi_instruction()
    .expect("zone deposit instruction");
    // The canonical `zone_auth` PDA address, but without a signature: only the
    // zone program's `invoke_signed` can supply one, and the flag is checked
    // before the account is even loaded.
    ix.accounts
        .get_mut(2)
        .expect("zone authority account")
        .is_signer = false;

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&depositor])
        .expect_err("unsigned zone config must fail");
    Rejection::custom(u32::from(AccountError::InvalidSigner)).assert_litesvm(err);
}

#[test]
fn zone_deposit_rejects_malformed_payload_exactly() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(2_000_000_000);
    let tree = pool.tree.pubkey();
    let data = pool
        .rpc
        .zone_sol_shield_data(1_000_000, [3u8; 32], [4u8; 32]);
    let mut ix = ZoneDeposit {
        tree,
        depositor: depositor.pubkey(),
        zone_program_id: Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID),
        deposits: vec![data],
    }
    .cpi_instruction()
    .expect("zone deposit instruction");
    // Parsing runs before any account or signer check, so the zone_config
    // signature is irrelevant here (and impossible at transaction level).
    ix.accounts
        .get_mut(2)
        .expect("zone authority account")
        .is_signer = false;

    let mut truncated = ix.clone();
    truncated.data.pop();
    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[truncated], &[&depositor])
        .expect_err("truncated zone deposit payload must fail");
    Rejection::pool(ShieldedPoolError::InvalidInstructionData).assert_litesvm(err);

    let mut trailing = ix;
    trailing.data.push(0);
    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[trailing], &[&depositor])
        .expect_err("trailing zone deposit payload byte must fail");
    Rejection::pool(ShieldedPoolError::InvalidInstructionData).assert_litesvm(err);
}

/// SPP-shaped zone SOL deposit instruction (as a zone program would CPI it,
/// zone_config marked signer) with placeholder accounts. Only usable for
/// checks that fire before any account content is loaded.
fn mollusk_zone_deposit_fixture() -> (
    mollusk_svm::Mollusk,
    Instruction,
    Vec<(Pubkey, MolluskAccount)>,
) {
    let (mollusk, program_id) = setup_mollusk();
    let ix = ZoneDeposit {
        tree: Pubkey::new_unique(),
        depositor: Pubkey::new_unique(),
        zone_program_id: Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID),
        deposits: vec![ZoneAssetDeposit {
            deposit: AssetDeposit {
                asset: DepositAsset::Sol,
                view_tag: [1u8; 32],
                owner: [2u8; 32],
                blinding: [3u8; 32],
                amount: 1_000_000,
                utxo_data: None,
                memo: None,
            },
            zone_data_hash: [0u8; 32],
            zone_data: Vec::new(),
        }],
    }
    .cpi_instruction()
    .expect("zone deposit instruction");
    let accounts = snapshot_instruction_accounts(&ix, (&PROGRAM_ID_PUBKEY, program_id), |_| None);
    (mollusk, ix, accounts)
}

#[test]
fn mollusk_zone_deposit_rejects_an_unsigned_depositor_exactly() {
    let (mollusk, mut ix, accounts) = mollusk_zone_deposit_fixture();
    // zone_config (index 2) stays signed; the depositor signer check runs
    // first, before any account is loaded.
    ix.accounts.get_mut(1).expect("depositor account").is_signer = false;

    expect_err_exact(
        &mollusk,
        &ix,
        &accounts,
        ProgramError::Custom(u32::from(AccountError::InvalidSigner)),
    );
}

#[test]
fn mollusk_zone_deposit_rejects_fewer_than_four_accounts_exactly() {
    let (mollusk, mut ix, accounts) = mollusk_zone_deposit_fixture();
    ix.accounts.truncate(3);

    // The zone_config loader fires before the settlement accounts are needed,
    // so truncation surfaces as an InvalidZoneConfig rejection, not a bare
    // account-count error.
    expect_err_exact(
        &mollusk,
        &ix,
        &accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidZoneConfig as u32),
    );
}

#[test]
fn mollusk_deposit_rejects_fewer_than_three_accounts_exactly() {
    let (mollusk, mut valid, accounts) = deposit_fixture();
    valid.accounts.truncate(2);

    // The account iterator reports the shortfall as the account-checks
    // NotEnoughAccountKeys custom error.
    expect_err_exact(
        &mollusk,
        &valid,
        &accounts,
        ProgramError::Custom(u32::from(AccountError::NotEnoughAccountKeys)),
    );
}

#[test]
fn mollusk_deposit_rejects_truncated_data_exactly() {
    let (mollusk, valid, accounts) = deposit_fixture();
    let mut truncated = valid;
    truncated.data = vec![tag::DEPOSIT, 1, 2, 3];

    expect_err_exact(
        &mollusk,
        &truncated,
        &accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidInstructionData as u32),
    );
}

#[test]
fn mollusk_deposit_rejects_every_account_privilege_downgrade() {
    let (mollusk, valid, accounts) = deposit_fixture();
    // Metas: [0] tree, [1] depositor (signer), [2] system program, [3] SOL
    // vault, [4] shielded-pool program. The signer and trailing-account cells
    // have stable errors; the remaining downgrades shift the account shape, so
    // only deterministic rejection is pinned.
    let program_index = valid.accounts.len().saturating_sub(1);
    sweep_account_matrix(&mollusk, &valid, &accounts, |mutation| match mutation {
        AccountMutation::Unsign { index: 1 } => {
            Expected::Err(ProgramError::Custom(u32::from(AccountError::InvalidSigner)))
        }
        AccountMutation::Readonly { index: 4 } => Expected::Success,
        AccountMutation::Remove { index } if index == program_index => Expected::Err(
            ProgramError::Custom(u32::from(AccountError::NotEnoughAccountKeys)),
        ),
        _ => Expected::Rejected,
    });
}

#[test]
fn mollusk_deposit_rejects_wrong_program_account_exactly() {
    let (mollusk, valid, accounts) = deposit_fixture();
    let wrong_program = Pubkey::new_unique();
    let mut wrong_program_ix = valid;
    *wrong_program_ix
        .accounts
        .last_mut()
        .expect("program account") = AccountMeta {
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
            owner: Pubkey::new_from_array([0u8; 32]),
            executable: false,
            rent_epoch: 0,
        },
    );

    expect_err_exact(
        &mollusk,
        &wrong_program_ix,
        &wrong_program_accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidSettlementAccounts as u32),
    );
}

#[test]
fn mollusk_deposit_rejects_reordered_accounts_exactly() {
    let (mollusk, mut valid, accounts) = deposit_fixture();
    // The depositor slot now holds the (unsigned) tree key, so the signer
    // check is the branch that fires.
    valid.accounts.swap(0, 1);
    expect_err_exact(
        &mollusk,
        &valid,
        &accounts,
        ProgramError::Custom(u32::from(AccountError::InvalidSigner)),
    );
}

#[test]
fn mollusk_deposit_rejects_wrong_tree_owner_exactly() {
    let (mollusk, valid, mut accounts) = deposit_fixture();
    accounts.first_mut().expect("tree account").1.owner = Pubkey::new_from_array([0x55; 32]);
    expect_err_exact(
        &mollusk,
        &valid,
        &accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidTreeAccounts as u32),
    );
}

#[test]
fn mollusk_deposit_rejects_truncated_tree_exactly() {
    let (mollusk, valid, mut accounts) = deposit_fixture();
    accounts
        .first_mut()
        .expect("tree account")
        .1
        .data
        .truncate(1);
    expect_err_exact(
        &mollusk,
        &valid,
        &accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidTreeAccounts as u32),
    );
}

#[test]
fn mollusk_deposit_rejects_unfunded_depositor_exactly() {
    let (mollusk, valid, mut accounts) = deposit_fixture();
    accounts.get_mut(1).expect("depositor account").1.lamports = 0;
    // The settle transfer inside the system-program CPI is what fails.
    expect_err_exact(
        &mollusk,
        &valid,
        &accounts,
        ProgramError::Custom(SystemError::ResultWithNegativeLamports as u32),
    );
}
