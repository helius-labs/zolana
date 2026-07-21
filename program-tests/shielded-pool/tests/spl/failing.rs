use solana_instruction::AccountMeta;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{error::ShieldedPoolError, pda};
use zolana_program_test::ZolanaProgramTest;
use zolana_test_utils::litesvm_asserts::{assert_custom, assert_pool_error};

use crate::support::{register_mint, spl_depositor, Pool};

fn spl_accounts(
    tree: Pubkey,
    depositor: Pubkey,
    user_token: Pubkey,
    mint: Pubkey,
) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(tree, false),
        AccountMeta::new(depositor, true),
        AccountMeta::new(user_token, false),
        AccountMeta::new(pda::spl_asset_vault(&mint), false),
        AccountMeta::new_readonly(pda::spl_asset_registry(&mint), false),
        AccountMeta::new_readonly(ZolanaProgramTest::token_program_id(), false),
        AccountMeta::new_readonly(zolana_interface::PROGRAM_ID_PUBKEY, false),
    ]
}

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
    assert_pool_error(err, ShieldedPoolError::InvalidSplAssetRegistry);
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
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
    assert!(pool
        .rpc
        .account_data(&pda::spl_asset_registry(&mint))
        .is_none());
}

#[test]
fn spl_deposit_rejects_foreign_source() {
    let mut pool = Pool::initialized();
    let (mint_a, _, _) = register_mint(&mut pool);
    let (depositor, _) = spl_depositor(&mut pool, mint_a, 1_000_000);
    let tree = pool.tree.pubkey();
    let data = ZolanaProgramTest::spl_shield_data(1_000, [1u8; 32], [1u8; 31]);
    let other_owner = Keypair::new();
    let foreign_token = pool
        .rpc
        .create_token_account(&mint_a, &other_owner.pubkey())
        .expect("foreign token account");
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
    assert_pool_error(err, ShieldedPoolError::InvalidSettlementAccounts);
}

#[test]
fn spl_deposit_rejects_noncanonical_vault() {
    let mut pool = Pool::initialized();
    let (mint_a, _, _) = register_mint(&mut pool);
    let (depositor, user_token) = spl_depositor(&mut pool, mint_a, 1_000_000);
    let tree = pool.tree.pubkey();
    let data = ZolanaProgramTest::spl_shield_data(1_000, [1u8; 32], [1u8; 31]);
    let decoy_vault = pool
        .rpc
        .create_token_account(&mint_a, &pda::shielded_pool_cpi_authority())
        .expect("decoy vault");
    let mut wrong_vault = spl_accounts(tree, depositor.pubkey(), user_token, mint_a);
    *wrong_vault.get_mut(3).expect("vault account") = AccountMeta::new(decoy_vault, false);

    let err = pool
        .rpc
        .deposit_with_accounts(wrong_vault, &depositor, &data)
        .expect_err("noncanonical vault must fail");
    assert_pool_error(err, ShieldedPoolError::InvalidSettlementAccounts);
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
    let data = ZolanaProgramTest::spl_shield_data(1_000, [1u8; 32], [1u8; 31]);
    let mint_b = pool.rpc.create_mint().expect("second mint");
    let token_b = pool
        .rpc
        .create_token_account(&mint_b, &depositor.pubkey())
        .expect("mint B token account");
    pool.rpc
        .mint_to(&mint_b, &token_b, 1_000_000)
        .expect("fund mint B token account");

    let err = pool
        .rpc
        .deposit_with_accounts(
            spl_accounts(tree, depositor.pubkey(), token_b, mint_a),
            &depositor,
            &data,
        )
        .expect_err("mismatched mint must fail");
    assert_pool_error(err, ShieldedPoolError::InvalidSettlementAccounts);
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
        .deposit_spl(
            &tree,
            &depositor,
            &user_token,
            &mint,
            &ZolanaProgramTest::spl_shield_data(5_000, [3u8; 32], [3u8; 31]),
        )
        .expect_err("insufficient token funds must fail");
    assert_custom(err, spl_token::error::TokenError::InsufficientFunds as u32);
    assert_eq!(pool.rpc.state_root(&tree), Some(root_before));
    assert_eq!(pool.rpc.token_balance(&user_token), Some(1_000));
    assert_eq!(pool.rpc.token_balance(&vault), Some(0));
}
