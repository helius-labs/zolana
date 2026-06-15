//! SPL asset registration and public SPL-deposit settlement coverage.

mod common;

use common::{assert_custom, assert_pool_error, program_test_with_tree};
use shielded_pool_program::error::ShieldedPoolError;
use solana_instruction::AccountMeta;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::ZolanaProgramTest;
use zolana_test_utils::asserts::{assert_create_spl_interface, assert_spl_deposit};
use zolana_transaction::Wallet;

const TOKEN_INSUFFICIENT_FUNDS: u32 = 1;

fn spl_setup(balance: u64) -> Option<(ZolanaProgramTest, Keypair, Pubkey, Keypair, Pubkey)> {
    let (mut program_test, authority, tree) = program_test_with_tree()?;
    let mint = program_test.create_mint().expect("create_mint");
    program_test
        .create_spl_interface(&authority, &mint)
        .expect("create_spl_interface");
    let depositor = Keypair::new();
    program_test
        .airdrop(&depositor.pubkey(), 1_000_000_000)
        .expect("fund");
    let user_token = program_test
        .create_token_account(&mint, &depositor.pubkey())
        .expect("token account");
    program_test
        .mint_to(&mint, &user_token, balance)
        .expect("mint_to");
    Some((program_test, tree, mint, depositor, user_token))
}

#[test]
fn create_spl_interface_initializes_registry_and_vault() {
    let Some((mut program_test, authority, _tree)) = program_test_with_tree() else {
        return;
    };
    let mint = program_test.create_mint().expect("create_mint");

    let (registry, vault) = program_test
        .create_spl_interface(&authority, &mint)
        .expect("create_spl_interface");
    assert_create_spl_interface(&program_test, &registry, &vault, &mint, 2, 3);

    // Fresh blockhash so the byte-identical transaction is not deduped as
    // already processed.
    program_test.svm.expire_blockhash();
    let err = program_test
        .create_spl_interface(&authority, &mint)
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidSplAssetRegistry);

    let mint_b = program_test.create_mint().expect("create_mint");
    let (registry_b, vault_b) = program_test
        .create_spl_interface(&authority, &mint_b)
        .expect("create_spl_interface mint B");
    assert_create_spl_interface(&program_test, &registry_b, &vault_b, &mint_b, 3, 4);
}

#[test]
fn create_spl_interface_rejects_non_authority() {
    let Some((mut program_test, _authority, _tree)) = program_test_with_tree() else {
        return;
    };
    let mint = program_test.create_mint().expect("create_mint");

    let impostor = Keypair::new();
    program_test
        .airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let err = program_test
        .create_spl_interface(&impostor, &mint)
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
}

#[test]
fn spl_deposit_succeeds_and_event_is_faithful() {
    let Some((mut program_test, tree, mint, depositor, user_token)) = spl_setup(1_000_000) else {
        return;
    };
    let vault = program_test.spl_asset_vault_pda(&mint);
    let mut recipient =
        Wallet::new(ShieldedKeypair::new().expect("recipient keypair")).expect("wallet");
    let seed = [7u8; BLINDING_LEN];
    let data = ZolanaProgramTest::wallet_spl_shield_data(400_000, &recipient, &seed, 0)
        .expect("wallet deposit data");

    let vault_before = program_test.token_balance(&vault).expect("vault balance");
    let user_token_before = program_test
        .token_balance(&user_token)
        .expect("user token balance");
    let root_before = program_test.state_root(&tree.pubkey()).expect("root");
    let event = program_test
        .proofless_shield_spl(&tree, &depositor, &user_token, &mint, &data)
        .expect("deposit");

    assert_spl_deposit(
        &mut program_test,
        &tree.pubkey(),
        &mint,
        &vault,
        &user_token,
        &event,
        &data,
        400_000,
        vault_before,
        user_token_before,
        root_before,
        &mut recipient,
    );
}

fn spl_accounts(
    program_test: &ZolanaProgramTest,
    tree: &Pubkey,
    depositor: &Pubkey,
    user_token: &Pubkey,
    mint: &Pubkey,
) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(*tree, false),
        AccountMeta::new(*depositor, true),
        AccountMeta::new_readonly(program_test.cpi_authority(), false),
        AccountMeta::new(*user_token, false),
        AccountMeta::new(program_test.spl_asset_vault_pda(mint), false),
        AccountMeta::new_readonly(program_test.spl_asset_registry_pda(mint), false),
        AccountMeta::new_readonly(ZolanaProgramTest::token_program_id(), false),
        AccountMeta::new_readonly(program_test.program_id, false),
    ]
}

#[test]
fn rejects_deposit_from_foreign_token_account() {
    let Some((mut program_test, tree, mint, depositor, _user_token)) = spl_setup(1_000_000) else {
        return;
    };

    let other = Keypair::new();
    let other_token = program_test
        .create_token_account(&mint, &other.pubkey())
        .expect("token account");
    program_test
        .mint_to(&mint, &other_token, 1_000_000)
        .expect("mint_to");
    let accounts = spl_accounts(
        &program_test,
        &tree.pubkey(),
        &depositor.pubkey(),
        &other_token,
        &mint,
    );
    let err = program_test
        .proofless_shield_with_accounts(
            accounts,
            &depositor,
            &ZolanaProgramTest::spl_shield_data(1_000, [1u8; 32]),
        )
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidSettlementAccounts);
}

#[test]
fn rejects_non_canonical_vault() {
    let Some((mut program_test, tree, mint, depositor, user_token)) = spl_setup(1_000_000) else {
        return;
    };

    let decoy_vault = program_test
        .create_token_account(&mint, &program_test.cpi_authority())
        .expect("decoy vault");
    let mut accounts = spl_accounts(
        &program_test,
        &tree.pubkey(),
        &depositor.pubkey(),
        &user_token,
        &mint,
    );
    accounts[4] = AccountMeta::new(decoy_vault, false);
    let err = program_test
        .proofless_shield_with_accounts(
            accounts,
            &depositor,
            &ZolanaProgramTest::spl_shield_data(1_000, [1u8; 32]),
        )
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidSettlementAccounts);
}

#[test]
fn rejects_mint_mismatch() {
    let Some((mut program_test, tree, mint_a, depositor, _user_token)) = spl_setup(1_000_000)
    else {
        return;
    };

    let mint_b = program_test.create_mint().expect("mint B");
    let token_b = program_test
        .create_token_account(&mint_b, &depositor.pubkey())
        .expect("token account");
    program_test
        .mint_to(&mint_b, &token_b, 1_000_000)
        .expect("mint_to");
    let accounts = spl_accounts(
        &program_test,
        &tree.pubkey(),
        &depositor.pubkey(),
        &token_b,
        &mint_a,
    );
    let err = program_test
        .proofless_shield_with_accounts(
            accounts,
            &depositor,
            &ZolanaProgramTest::spl_shield_data(1_000, [1u8; 32]),
        )
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidSettlementAccounts);
}

#[test]
fn rejects_unaffordable_spl_deposit() {
    let Some((mut program_test, tree, mint, depositor, user_token)) = spl_setup(1_000) else {
        return;
    };

    let err = program_test
        .proofless_shield_spl(
            &tree,
            &depositor,
            &user_token,
            &mint,
            &ZolanaProgramTest::spl_shield_data(5_000, [3u8; 32]),
        )
        .unwrap_err();
    assert_custom(err, TOKEN_INSUFFICIENT_FUNDS);
}
