use solana_account::Account as MolluskAccount;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_system_interface::error::SystemError;
use zolana_account_checks::AccountError;
use zolana_hasher::primitives::BN254_SCALAR_MODULUS_BE;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        tag, DepositAsset, DepositAssetKind, DepositEntry, EncryptedRingDepositData,
        RingAssetDeposit, RingDeposit,
    },
    pda, PROGRAM_ID_PUBKEY,
};
use zolana_program_test::{Rejection, ZolanaProgramTest, RING_TEST_PROGRAM_ID};

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
    let tree = pool.tree;
    let data = ZolanaProgramTest::sol_shield_data(0, [2u8; 32]);

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
    let tree = pool.tree;
    let zero_spl = ZolanaProgramTest::spl_shield_data(0, [3u8; 32], &mint, &user_token);

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
        amount,
        utxo_data: None,
        memo: None,
    }
}

fn spl_asset_kind(mint: &Pubkey) -> DepositAssetKind {
    DepositAssetKind::Spl {
        spl_interface_bump: pda::spl_interface_with_bump(mint).1,
    }
}

#[test]
fn deposit_batch_rejects_an_empty_batch() {
    // The builder refuses empty batches (`DepositBuildError::EmptyBatch`), so
    // only raw instruction data can reach this on-chain check.
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(5_000_000_000);
    let tree = pool.tree;

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
fn deposit_batch_rejects_a_non_canonical_owner() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(5_000_000_000);
    let tree = pool.tree;
    let mut entry = raw_entry(1_000);
    entry.owner = BN254_SCALAR_MODULUS_BE;

    let err = raw_deposit_batch(
        &mut pool.rpc,
        tree,
        &depositor,
        vec![DepositAssetKind::Sol],
        vec![raw_entry(1_000), entry],
        vec![sol_group_accounts()],
    )
    .expect_err("non-canonical deposit owner must fail");
    Rejection::pool(ShieldedPoolError::NonCanonicalDepositField).assert_litesvm(err);
}

#[test]
fn deposit_batch_rejects_an_out_of_range_asset_index() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(5_000_000_000);
    let tree = pool.tree;
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
    let tree = pool.tree;

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
    let tree = pool.tree;

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
fn deposit_batch_rejects_more_assets_than_any_layout_supports() {
    // Six declared asset groups overflow MAX_DEPOSIT_ASSETS (5); the count gate
    // fires at account parsing, before any settlement account is read.
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(5_000_000_000);
    let tree = pool.tree;

    let err = raw_deposit_batch(
        &mut pool.rpc,
        tree,
        &depositor,
        vec![DepositAssetKind::Sol; 6],
        vec![raw_entry(1_000)],
        vec![sol_group_accounts(); 6],
    )
    .expect_err("six declared assets must fail");
    Rejection::pool(ShieldedPoolError::TooManyDepositAssets).assert_litesvm(err);
}

#[test]
fn deposit_batch_rejects_an_empty_assets_list() {
    // Zero declared asset groups is rejected at account parsing, before any
    // settlement account is read. The batch itself is non-empty, so the
    // empty-batch gate (7029) is not the branch that fires.
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(5_000_000_000);
    let tree = pool.tree;

    let err = raw_deposit_batch(
        &mut pool.rpc,
        tree,
        &depositor,
        Vec::new(),
        vec![raw_entry(1_000)],
        Vec::new(),
    )
    .expect_err("an empty assets list must fail");
    Rejection::pool(ShieldedPoolError::InvalidSettlementAccounts).assert_litesvm(err);
}

#[test]
fn deposit_batch_rejects_declaring_the_same_mint_twice() {
    let mut pool = Pool::initialized();
    let (mint, _, _) = register_mint(&mut pool);
    let (depositor, user_token) = spl_depositor(&mut pool, mint, 1_000_000);
    let tree = pool.tree;
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
    let tree = pool.tree;
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
    let tree = pool.tree;
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
    let tree = pool.tree;
    let mut extra = sol_deposit_accounts(&pool.rpc, tree, depositor.pubkey());
    extra.insert(5, AccountMeta::new_readonly(pool.rpc.payer.pubkey(), false));

    let err = raw_sol_deposit(&mut pool.rpc, &depositor, extra)
        .expect_err("extra settlement account must fail");
    Rejection::pool(ShieldedPoolError::InvalidSettlementAccounts).assert_litesvm(err);
}

#[test]
fn sol_deposit_rejects_a_readonly_depositor() {
    // INV-DEPOSIT-03/04, current form: the SOL rail has no separate source
    // account -- the depositor signer IS the transfer source by construction
    // (`deposit/account.rs` builds `SettlementAccountsSol { user_account: depositor }`),
    // so a foreign funding source is unforgeable and there is nothing to swap.
    // What remains of the property is the writability requirement:
    // `validate_sol_settlement` rejects a read-only depositor.
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(2_000_000_000);
    let tree = pool.tree;
    let mut readonly_depositor = sol_deposit_accounts(&pool.rpc, tree, depositor.pubkey());
    *readonly_depositor.get_mut(1).expect("depositor account") =
        AccountMeta::new_readonly(depositor.pubkey(), true);

    let err = raw_sol_deposit(&mut pool.rpc, &depositor, readonly_depositor)
        .expect_err("read-only depositor must fail");
    Rejection::pool(ShieldedPoolError::InvalidSettlementAccounts).assert_litesvm(err);
}

#[test]
fn sol_deposit_rejects_wrong_system_program_account() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(2_000_000_000);
    let tree = pool.tree;
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
    let tree = pool.tree;
    let mut readonly_interface = sol_deposit_accounts(&pool.rpc, tree, depositor.pubkey());
    *readonly_interface.get_mut(3).expect("vault account") =
        AccountMeta::new_readonly(pda::sol_interface(), false);

    let err = raw_sol_deposit(&mut pool.rpc, &depositor, readonly_interface)
        .expect_err("read-only sol_interface must fail");
    Rejection::pool(ShieldedPoolError::InvalidSettlementAccounts).assert_litesvm(err);
}

#[test]
fn sol_deposit_rejects_foreign_tree_atomically() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(2_000_000_000);
    let tree = pool.tree;
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
    let tree = pool.tree;
    pool.rpc
        .pause_tree(&pool.authority, &pool.tree, true)
        .expect("pause tree");

    let err = pool
        .rpc
        .deposit_sol(&tree, &depositor, 1_000_000, [4u8; 32])
        .expect_err("paused tree deposit must fail");
    Rejection::pool(ShieldedPoolError::TreePaused).assert_litesvm(err);
}

#[test]
fn paused_tree_rejects_ring_deposit() {
    let mut pool = Pool::initialized();
    pool.rpc
        .load_ring_test_program()
        .expect("load ring test program");
    let ring_authority = pool.authority.insecure_clone();
    pool.rpc
        .create_ring_config(&ring_authority, &ring_authority.pubkey(), true)
        .expect("create ring config");
    let depositor = pool.funded_signer(2_000_000_000);
    let tree = pool.tree;
    pool.rpc
        .pause_tree(&pool.authority, &pool.tree, true)
        .expect("pause tree");
    let data = pool
        .rpc
        .ring_sol_shield_data(1_000_000, [4u8; 32], [4u8; 32]);

    let err = pool
        .rpc
        .ring_deposit(&tree, &depositor, &data)
        .expect_err("paused tree ring deposit must fail");
    Rejection::pool(ShieldedPoolError::TreePaused).assert_litesvm(err);
    pool.rpc
        .last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[pool.rpc.payer.pubkey()]);
}

#[test]
fn paused_ring_rejects_ring_deposit_and_unpause_restores_it() {
    let mut pool = Pool::initialized();
    pool.rpc
        .load_ring_test_program()
        .expect("load ring test program");
    let ring_authority = pool.authority.insecure_clone();
    let ring_config = pool
        .rpc
        .create_ring_config(&ring_authority, &ring_authority.pubkey(), true)
        .expect("create ring config");
    pool.rpc
        .update_ring_config(&ring_authority, &ring_config, true, true)
        .expect("pause ring config");

    let depositor = pool.funded_signer(2_000_000_000);
    let tree = pool.tree;
    let tree_before = pool.rpc.account_data(&tree).expect("tree data");
    let data = pool
        .rpc
        .ring_sol_shield_data(1_000_000, [4u8; 32], [4u8; 32]);

    let err = pool
        .rpc
        .ring_deposit(&tree, &depositor, &data)
        .expect_err("paused ring deposit must fail");
    Rejection::pool(ShieldedPoolError::RingPaused).assert_litesvm(err);
    assert_eq!(
        pool.rpc.account_data(&tree).expect("tree data"),
        tree_before,
        "paused ring deposit must not mutate the tree"
    );
    pool.rpc
        .last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[pool.rpc.payer.pubkey()]);

    pool.rpc
        .update_ring_config(&ring_authority, &ring_config, true, false)
        .expect("unpause ring config");
    pool.rpc
        .ring_deposit(&tree, &depositor, &data)
        .expect("ring deposit succeeds after unpause");
}

#[test]
fn ring_deposit_rejects_a_signer_that_is_not_the_ring_authority() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(5_000_000_000);
    let tree = pool.tree;
    let data = pool
        .rpc
        .ring_sol_shield_data(1_000_000, [3u8; 32], [4u8; 32]);
    let mut ix = RingDeposit {
        tree,
        depositor: depositor.pubkey(),
        ring_program_id: Pubkey::new_from_array(RING_TEST_PROGRAM_ID),
        deposits: vec![data],
    }
    .cpi_instruction()
    .expect("ring deposit instruction");
    ix.accounts
        .get_mut(2)
        .expect("ring authority account")
        .pubkey = depositor.pubkey();

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&depositor])
        .expect_err("wrong ring signer must fail");
    Rejection::pool(ShieldedPoolError::InvalidRingConfig).assert_litesvm(err);
    pool.rpc
        .last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[pool.rpc.payer.pubkey()]);
}

#[test]
fn ring_deposit_rejects_an_unsigned_ring_config() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(5_000_000_000);
    let tree = pool.tree;
    let data = pool
        .rpc
        .ring_sol_shield_data(1_000_000, [3u8; 32], [4u8; 32]);
    let mut ix = RingDeposit {
        tree,
        depositor: depositor.pubkey(),
        ring_program_id: Pubkey::new_from_array(RING_TEST_PROGRAM_ID),
        deposits: vec![data],
    }
    .cpi_instruction()
    .expect("ring deposit instruction");
    // The canonical `ring_auth` PDA address, but without a signature: only the
    // ring program's `invoke_signed` can supply one, and the flag is checked
    // before the account is even loaded.
    ix.accounts
        .get_mut(2)
        .expect("ring authority account")
        .is_signer = false;

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&depositor])
        .expect_err("unsigned ring config must fail");
    Rejection::custom(u32::from(AccountError::InvalidSigner)).assert_litesvm(err);
    pool.rpc
        .last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[pool.rpc.payer.pubkey()]);
}

#[test]
fn ring_deposit_rejects_malformed_payload_exactly() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(2_000_000_000);
    let tree = pool.tree;
    let data = pool
        .rpc
        .ring_sol_shield_data(1_000_000, [3u8; 32], [4u8; 32]);
    let mut ix = RingDeposit {
        tree,
        depositor: depositor.pubkey(),
        ring_program_id: Pubkey::new_from_array(RING_TEST_PROGRAM_ID),
        deposits: vec![data],
    }
    .cpi_instruction()
    .expect("ring deposit instruction");
    // Parsing runs before any account or signer check, so the ring_config
    // signature is irrelevant here (and impossible at transaction level).
    ix.accounts
        .get_mut(2)
        .expect("ring authority account")
        .is_signer = false;

    let mut truncated = ix.clone();
    truncated.data.pop();
    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[truncated], &[&depositor])
        .expect_err("truncated ring deposit payload must fail");
    Rejection::pool(ShieldedPoolError::InvalidInstructionData).assert_litesvm(err);
    pool.rpc
        .last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[pool.rpc.payer.pubkey()]);

    let mut trailing = ix;
    trailing.data.push(0);
    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[trailing], &[&depositor])
        .expect_err("trailing ring deposit payload byte must fail");
    Rejection::pool(ShieldedPoolError::InvalidInstructionData).assert_litesvm(err);
    pool.rpc
        .last_transaction_trace()
        .expect("rejected transaction trace")
        .assert_rolled_back_except(&[pool.rpc.payer.pubkey()]);
}

/// SPP-shaped ring SOL deposit instruction (as a ring program would CPI it,
/// ring_config marked signer) with placeholder accounts. Only usable for
/// checks that fire before any account content is loaded.
fn mollusk_ring_deposit_fixture() -> (
    mollusk_svm::Mollusk,
    Instruction,
    Vec<(Pubkey, MolluskAccount)>,
) {
    let (mollusk, program_id) = setup_mollusk();
    let ix = RingDeposit {
        tree: Pubkey::new_unique(),
        depositor: Pubkey::new_unique(),
        ring_program_id: Pubkey::new_from_array(RING_TEST_PROGRAM_ID),
        deposits: vec![RingAssetDeposit {
            asset: DepositAsset::Sol,
            view_tag: [1u8; 32],
            owner_utxo_hash: [2u8; 32],
            amount: 1_000_000,
            data_hash: None,
            ring_data_hash: [0u8; 32],
            encrypted: EncryptedRingDepositData {
                tx_viewing_pk: [0u8; 33],
                salt: [0u8; 16],
                ciphertext: Vec::new(),
            },
        }],
    }
    .cpi_instruction()
    .expect("ring deposit instruction");
    let accounts = snapshot_instruction_accounts(&ix, (&PROGRAM_ID_PUBKEY, program_id), |_| None);
    (mollusk, ix, accounts)
}

#[test]
fn mollusk_ring_deposit_rejects_an_unsigned_depositor_exactly() {
    let (mollusk, mut ix, accounts) = mollusk_ring_deposit_fixture();
    // ring_config (index 2) stays signed; the depositor signer check runs
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
fn mollusk_ring_deposit_rejects_fewer_than_four_accounts_exactly() {
    let (mollusk, mut ix, accounts) = mollusk_ring_deposit_fixture();
    ix.accounts.truncate(3);

    // The ring_config loader fires before the settlement accounts are needed,
    // so truncation surfaces as an InvalidRingConfig rejection, not a bare
    // account-count error.
    expect_err_exact(
        &mollusk,
        &ix,
        &accounts,
        ProgramError::Custom(ShieldedPoolError::InvalidRingConfig as u32),
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
    // Metas: [0] tree, [1] depositor (signer), [2] shielded-pool program,
    // [3] system program, [4] SOL interface vault (writable). The signer and
    // fixed-privilege cells have stable errors; the remaining downgrades shift
    // the account shape, so only deterministic rejection is pinned.
    sweep_account_matrix(&mollusk, &valid, &accounts, |mutation| match mutation {
        AccountMutation::Unsign { index: 1 } => {
            Expected::Err(ProgramError::Custom(u32::from(AccountError::InvalidSigner)))
        }
        AccountMutation::Readonly { index: 2 } | AccountMutation::Readonly { index: 3 } => {
            Expected::Success
        }
        AccountMutation::Readonly { index: 4 } => Expected::Err(ProgramError::Custom(
            ShieldedPoolError::InvalidSettlementAccounts as u32,
        )),
        AccountMutation::Remove { index: 2 } => Expected::Err(ProgramError::Custom(
            ShieldedPoolError::InvalidSettlementAccounts as u32,
        )),
        AccountMutation::Remove { index } if index >= 3 => Expected::Err(ProgramError::Custom(
            u32::from(AccountError::NotEnoughAccountKeys),
        )),
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
        .get_mut(2)
        .expect("program account") = AccountMeta {
        pubkey: mollusk_pubkey(&wrong_program),
        is_signer: false,
        is_writable: false,
    };
    let mut wrong_program_accounts = accounts;
    *wrong_program_accounts.get_mut(2).expect("program account") = (
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
