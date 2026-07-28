use solana_instruction::{error::InstructionError, AccountMeta};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use spl_token_2022_interface::{
    extension::{transfer_fee::instruction::initialize_transfer_fee_config, ExtensionType},
    instruction::{initialize_account3, initialize_mint2},
    pod::{PodAccount, PodMint},
};
use zolana_account_checks::AccountError;
use zolana_interface::{error::ShieldedPoolError, instruction::CreateSplInterface, pda};
use zolana_program_test::{system_create_account_ix, test_blinding, Rejection, ZolanaProgramTest};
use zolana_test_utils::litesvm_asserts::{assert_custom, assert_instruction_error};

use shielded_pool_tests::support::fixtures::{register_mint, spl_accounts, spl_depositor, Pool};

#[test]
fn duplicate_spl_interface_registration_is_rejected_without_consuming_id() {
    let mut pool = Pool::initialized();
    let (mint_a, _, _) = register_mint(&mut pool);
    let counter_before = pool
        .rpc
        .account_data(&pda::spl_asset_counter())
        .expect("counter");

    let err = pool
        .rpc
        .create_spl_interface(&pool.authority, &mint_a)
        .expect_err("duplicate interface must fail");
    Rejection::pool(ShieldedPoolError::InvalidSplAssetRegistry).assert_litesvm(err);
    assert_eq!(
        pool.rpc.account_data(&pda::spl_asset_counter()),
        Some(counter_before),
        "failed duplicate must not consume an asset id"
    );
}

#[test]
fn spl_interface_creation_rejects_unauthorized_caller() {
    let mut pool = Pool::initialized();
    pool.rpc
        .ensure_asset_counter(&pool.authority)
        .expect("asset counter");
    let mint = pool.rpc.create_mint().expect("mint");
    let outsider = pool.funded_signer(1_000_000_000);

    let err = pool
        .rpc
        .create_spl_interface(&outsider, &mint)
        .expect_err("unauthorized interface creation must fail");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(err);
    assert!(pool
        .rpc
        .account_data(&pda::spl_asset_registry(&mint))
        .is_none());
}

#[test]
fn spl_interface_creation_rejects_a_wrong_token_program() {
    let mut pool = Pool::initialized();
    pool.rpc
        .ensure_asset_counter(&pool.authority)
        .expect("asset counter");
    let mint = pool.rpc.create_mint().expect("mint");
    let mut ix = CreateSplInterface {
        authority: pool.authority.pubkey(),
        mint,
        token_program: pda::spl_token_program_id(),
    }
    .instruction();
    ix.accounts.get_mut(7).expect("token program meta").pubkey = Pubkey::new_unique();

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&pool.authority])
        .expect_err("wrong token program must fail");
    // The program validates the token program account itself instead of
    // relying on the runtime's CPI-target check.
    Rejection::pool(ShieldedPoolError::UnsupportedSplTokenProgram).assert_litesvm(err);
}

#[test]
fn spl_interface_creation_rejects_a_wrong_system_program() {
    let mut pool = Pool::initialized();
    pool.rpc
        .ensure_asset_counter(&pool.authority)
        .expect("asset counter");
    let mint = pool.rpc.create_mint().expect("mint");
    let mut ix = CreateSplInterface {
        authority: pool.authority.pubkey(),
        mint,
        token_program: pda::spl_token_program_id(),
    }
    .instruction();
    ix.accounts.get_mut(6).expect("system program meta").pubkey = Pubkey::new_unique();

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&pool.authority])
        .expect_err("wrong system program must fail");
    assert_instruction_error(err, InstructionError::IncorrectProgramId);
}

#[test]
fn spl_interface_creation_rejects_an_unsigned_authority() {
    let mut pool = Pool::initialized();
    pool.rpc
        .ensure_asset_counter(&pool.authority)
        .expect("asset counter");
    let mint = pool.rpc.create_mint().expect("mint");
    let mut ix = CreateSplInterface {
        authority: pool.authority.pubkey(),
        mint,
        token_program: pda::spl_token_program_id(),
    }
    .instruction();
    ix.accounts.first_mut().expect("authority meta").is_signer = false;

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("unsigned authority must fail");
    assert_custom(err, u32::from(AccountError::InvalidSigner));
    assert!(
        pool.rpc
            .account_data(&pda::spl_asset_registry(&mint))
            .is_none(),
        "rejected creation must not allocate the registry"
    );
}

#[test]
fn spl_interface_creation_rejects_a_noncanonical_registry_pda() {
    let mut pool = Pool::initialized();
    pool.rpc
        .ensure_asset_counter(&pool.authority)
        .expect("asset counter");
    let mint = pool.rpc.create_mint().expect("mint");
    let mut ix = CreateSplInterface {
        authority: pool.authority.pubkey(),
        mint,
        token_program: pda::spl_token_program_id(),
    }
    .instruction();
    ix.accounts.get_mut(3).expect("registry meta").pubkey = Pubkey::new_unique();

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&pool.authority])
        .expect_err("noncanonical registry PDA must fail");
    Rejection::pool(ShieldedPoolError::InvalidPda).assert_litesvm(err);
    assert!(
        pool.rpc
            .account_data(&pda::spl_asset_registry(&mint))
            .is_none(),
        "rejected creation must not allocate the registry"
    );
}

#[test]
fn spl_interface_creation_rejects_a_noncanonical_vault_pda() {
    let mut pool = Pool::initialized();
    pool.rpc
        .ensure_asset_counter(&pool.authority)
        .expect("asset counter");
    let mint = pool.rpc.create_mint().expect("mint");
    let mut ix = CreateSplInterface {
        authority: pool.authority.pubkey(),
        mint,
        token_program: pda::spl_token_program_id(),
    }
    .instruction();
    ix.accounts.get_mut(5).expect("vault meta").pubkey = Pubkey::new_unique();

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&pool.authority])
        .expect_err("noncanonical vault PDA must fail");
    Rejection::pool(ShieldedPoolError::InvalidPda).assert_litesvm(err);
    assert!(
        pool.rpc
            .account_data(&pda::spl_asset_vault(&mint))
            .is_none(),
        "rejected creation must not allocate the vault"
    );
}

#[test]
fn spl_interface_creation_rejects_a_cosplay_counter_account() {
    let mut pool = Pool::initialized();
    // The counter is never created; a funded system-owned account stands in.
    let mint = pool.rpc.create_mint().expect("mint");
    let impostor = Pubkey::new_unique();
    pool.rpc
        .airdrop(&impostor, 1_000_000)
        .expect("fund impostor");
    let mut ix = CreateSplInterface {
        authority: pool.authority.pubkey(),
        mint,
        token_program: pda::spl_token_program_id(),
    }
    .instruction();
    ix.accounts.get_mut(2).expect("counter meta").pubkey = impostor;

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&pool.authority])
        .expect_err("a non-counter account in the counter slot must fail");
    Rejection::pool(ShieldedPoolError::InvalidSplAssetRegistry).assert_litesvm(err);
    assert!(
        pool.rpc
            .account_data(&pda::spl_asset_registry(&mint))
            .is_none(),
        "rejected creation must not allocate the registry"
    );
}

#[test]
fn spl_interface_creation_rejects_trailing_instruction_bytes() {
    let mut pool = Pool::initialized();
    pool.rpc
        .ensure_asset_counter(&pool.authority)
        .expect("asset counter");
    let mint = pool.rpc.create_mint().expect("mint");
    let mut ix = CreateSplInterface {
        authority: pool.authority.pubkey(),
        mint,
        token_program: pda::spl_token_program_id(),
    }
    .instruction();
    ix.data.push(0xFF);

    let err = pool
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&pool.authority])
        .expect_err("non-empty instruction payload must fail");
    Rejection::pool(ShieldedPoolError::InvalidInstructionData).assert_litesvm(err);
}

#[test]
fn spl_deposit_rejects_foreign_source() {
    let mut pool = Pool::initialized();
    let (mint_a, _, _) = register_mint(&mut pool);
    let (depositor, _) = spl_depositor(&mut pool, mint_a, 1_000_000);
    let tree = pool.tree.pubkey();
    let other_owner = Keypair::new();
    let foreign_token = pool
        .rpc
        .create_token_account(&mint_a, &other_owner.pubkey())
        .expect("foreign token account");
    let data =
        ZolanaProgramTest::spl_shield_data(1_000, [1u8; 32], [1u8; 32], &mint_a, &foreign_token);
    pool.rpc
        .mint_to(&mint_a, &foreign_token, 1_000_000)
        .expect("fund foreign token account");

    let err = pool
        .rpc
        .deposit_with_accounts(
            spl_accounts(tree, depositor.pubkey(), foreign_token, mint_a),
            &depositor,
            &data,
        )
        .expect_err("foreign source must fail");
    Rejection::pool(ShieldedPoolError::InvalidSettlementAccounts).assert_litesvm(err);
}

#[test]
fn spl_deposit_rejects_noncanonical_vault() {
    let mut pool = Pool::initialized();
    let (mint_a, _, _) = register_mint(&mut pool);
    let (depositor, user_token) = spl_depositor(&mut pool, mint_a, 1_000_000);
    let tree = pool.tree.pubkey();
    let data =
        ZolanaProgramTest::spl_shield_data(1_000, [1u8; 32], [1u8; 32], &mint_a, &user_token);
    let decoy_vault = pool
        .rpc
        .create_token_account(&mint_a, &pda::shielded_pool_cpi_authority())
        .expect("decoy vault");
    let mut wrong_vault = spl_accounts(tree, depositor.pubkey(), user_token, mint_a);
    *wrong_vault.get_mut(5).expect("vault account") = AccountMeta::new(decoy_vault, false);

    let err = pool
        .rpc
        .deposit_with_accounts(wrong_vault, &depositor, &data)
        .expect_err("noncanonical vault must fail");
    Rejection::pool(ShieldedPoolError::InvalidSettlementAccounts).assert_litesvm(err);
}

#[test]
fn spl_deposit_rejects_mismatched_mint_atomically() {
    let mut pool = Pool::initialized();
    let (mint_a, _, vault) = register_mint(&mut pool);
    let (depositor, user_token) = spl_depositor(&mut pool, mint_a, 1_000_000);
    let tree = pool.tree.pubkey();
    let root_before = pool.rpc.state_root(&tree).expect("root");
    let user_before = pool.rpc.token_balance(&user_token).expect("user balance");
    let vault_before = pool.rpc.token_balance(&vault).expect("vault balance");
    let mint_b = pool.rpc.create_mint().expect("second mint");
    let token_b = pool
        .rpc
        .create_token_account(&mint_b, &depositor.pubkey())
        .expect("mint B token account");
    pool.rpc
        .mint_to(&mint_b, &token_b, 1_000_000)
        .expect("fund mint B token account");
    let data = ZolanaProgramTest::spl_shield_data(1_000, [1u8; 32], [1u8; 32], &mint_a, &token_b);

    let err = pool
        .rpc
        .deposit_with_accounts(
            spl_accounts(tree, depositor.pubkey(), token_b, mint_a),
            &depositor,
            &data,
        )
        .expect_err("mismatched mint must fail");
    Rejection::pool(ShieldedPoolError::InvalidSettlementAccounts).assert_litesvm(err);
    assert_eq!(pool.rpc.state_root(&tree), Some(root_before));
    assert_eq!(pool.rpc.token_balance(&user_token), Some(user_before));
    assert_eq!(pool.rpc.token_balance(&vault), Some(vault_before));
}

#[test]
fn spl_deposit_rejects_insufficient_funds_atomically() {
    let mut pool = Pool::initialized();
    let (mint, _, vault) = register_mint(&mut pool);
    let (depositor, user_token) = spl_depositor(&mut pool, mint, 1_000);
    let tree = pool.tree.pubkey();
    let root_before = pool.rpc.state_root(&tree).expect("root");

    let err = pool
        .rpc
        .deposit(
            &tree,
            &depositor,
            &ZolanaProgramTest::spl_shield_data(5_000, [3u8; 32], [3u8; 32], &mint, &user_token),
        )
        .expect_err("insufficient token funds must fail");
    assert_custom(err, spl_token::error::TokenError::InsufficientFunds as u32);
    assert_eq!(pool.rpc.state_root(&tree), Some(root_before));
    assert_eq!(pool.rpc.token_balance(&user_token), Some(1_000));
    assert_eq!(pool.rpc.token_balance(&vault), Some(0));
}

fn create_transfer_fee_mint(
    rpc: &mut ZolanaProgramTest,
    transfer_fee_basis_points: u16,
    maximum_fee: u64,
) -> Pubkey {
    let token_program = ZolanaProgramTest::token_2022_program_id();
    let mint = Keypair::new();
    let mint_len =
        ExtensionType::try_calculate_account_len::<PodMint>(&[ExtensionType::TransferFeeConfig])
            .expect("transfer-fee mint length");
    let payer = rpc.payer.insecure_clone();
    let create_ix = system_create_account_ix(
        &payer.pubkey(),
        &mint.pubkey(),
        rpc.svm.minimum_balance_for_rent_exemption(mint_len),
        mint_len as u64,
        &token_program,
    );
    let init_fee_ix = initialize_transfer_fee_config(
        &token_program,
        &mint.pubkey(),
        Some(&payer.pubkey()),
        Some(&payer.pubkey()),
        transfer_fee_basis_points,
        maximum_fee,
    )
    .expect("initialize transfer fee config");
    let init_mint_ix = initialize_mint2(&token_program, &mint.pubkey(), &payer.pubkey(), None, 9)
        .expect("initialize transfer-fee mint");

    rpc.create_and_send_default_payer_transaction(
        &[create_ix, init_fee_ix, init_mint_ix],
        &[&mint],
    )
    .expect("create transfer-fee mint");
    mint.pubkey()
}

fn create_transfer_fee_token_account(
    rpc: &mut ZolanaProgramTest,
    mint: &Pubkey,
    owner: &Pubkey,
) -> Pubkey {
    let token_program = ZolanaProgramTest::token_2022_program_id();
    let account = Keypair::new();
    let account_len =
        ExtensionType::try_calculate_account_len::<PodAccount>(&[ExtensionType::TransferFeeAmount])
            .expect("transfer-fee token-account length");
    let create_ix = system_create_account_ix(
        &rpc.payer.pubkey(),
        &account.pubkey(),
        rpc.svm.minimum_balance_for_rent_exemption(account_len),
        account_len as u64,
        &token_program,
    );
    let init_ix = initialize_account3(&token_program, &account.pubkey(), mint, owner)
        .expect("initialize transfer-fee token account");

    rpc.create_and_send_default_payer_transaction(&[create_ix, init_ix], &[&account])
        .expect("create transfer-fee token account");
    account.pubkey()
}

#[test]
fn transfer_fee_deposit_is_rejected_when_vault_receives_less_than_nominal_amount() {
    let mut pool = Pool::initialized();
    pool.rpc
        .ensure_asset_counter(&pool.authority)
        .expect("asset counter");

    // One percent of 400 is 4.
    let token_program = ZolanaProgramTest::token_2022_program_id();
    let mint = create_transfer_fee_mint(&mut pool.rpc, 100, u64::MAX);
    let (_, vault) = pool
        .rpc
        .create_spl_interface_with_program(&pool.authority, &mint, token_program)
        .expect("create transfer-fee interface");
    let depositor = pool.funded_signer(1_000_000_000);
    let source = create_transfer_fee_token_account(&mut pool.rpc, &mint, &depositor.pubkey());
    pool.rpc
        .mint_to_with_program(&mint, &source, 1_000, token_program)
        .expect("mint Token-2022 balance");

    let data = ZolanaProgramTest::spl_shield_data_with_program(
        400,
        [1u8; 32],
        test_blinding(7),
        &mint,
        &source,
        token_program,
    );
    let tree = pool.tree.pubkey();
    let root_before = pool.rpc.state_root(&tree).expect("root");

    let err = pool
        .rpc
        .deposit(&tree, &depositor, &data)
        .expect_err("396 credited for a nominal 400 deposit must be rejected");
    Rejection::pool(ShieldedPoolError::PublicSettlementFailed).assert_litesvm(err);

    // The failed instruction rolls back both the fee-bearing transfer and the
    // shielded-state append.
    assert_eq!(pool.rpc.token_balance(&source), Some(1_000));
    assert_eq!(pool.rpc.token_balance(&vault), Some(0));
    assert_eq!(pool.rpc.state_root(&tree), Some(root_before));
}
