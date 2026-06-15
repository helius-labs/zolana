//! SPL asset registration and SPL-deposit settlement steps.

use cucumber::{given, then, when};
use solana_instruction::AccountMeta;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::instruction::{ProoflessShieldAccounts, ProoflessShieldSplAccounts};
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::ZolanaProgramTest;
use zolana_test_utils::asserts::{assert_create_spl_interface, assert_spl_deposit};
use zolana_transaction::Wallet;

use crate::common::assert_custom;
use crate::ShieldedPoolWorld;

const TOKEN_INSUFFICIENT_FUNDS: u32 = 1;

fn spl_accounts(
    program_test: &ZolanaProgramTest,
    tree: &Pubkey,
    depositor: &Pubkey,
    user_token: &Pubkey,
    mint: &Pubkey,
) -> Vec<AccountMeta> {
    ProoflessShieldAccounts::spl(
        *tree,
        *depositor,
        ProoflessShieldSplAccounts {
            user_token: *user_token,
            vault: program_test.spl_asset_vault_pda(mint),
            registry: program_test.spl_asset_registry_pda(mint),
            token_program: ZolanaProgramTest::token_program_id(),
        },
    )
    .account_metas()
}

// === SPL interface registration ===

#[given(expr = "a registered mint")]
#[when(expr = "the authority registers an SPL interface for a mint")]
fn register_spl_interface(world: &mut ShieldedPoolWorld) {
    let mint = world.rpc().create_mint().expect("create_mint");
    let authority = world.authority().insecure_clone();
    let (registry, vault) = world
        .rpc()
        .create_spl_interface(&authority, &mint)
        .expect("create_spl_interface");
    world.mint = Some(mint);
    world.spl_registry = Some(registry);
    world.spl_vault = Some(vault);
}

#[then(expr = "the registry and vault are initialized with indices {int} and {int}")]
fn assert_interface(world: &mut ShieldedPoolWorld, registry_index: u64, vault_index: u64) {
    let mint = world.mint();
    let registry = world.spl_registry.expect("registry set");
    let vault = world.spl_vault.expect("vault set");
    let rpc = world.rpc_ref();
    assert_create_spl_interface(rpc, &registry, &vault, &mint, registry_index, vault_index);
}

#[when(expr = "the authority registers the same SPL interface again")]
fn register_same_interface(world: &mut ShieldedPoolWorld) {
    world.rpc().svm.expire_blockhash();
    let mint = world.mint();
    let authority = world.authority().insecure_clone();
    let err = world
        .rpc()
        .create_spl_interface(&authority, &mint)
        .unwrap_err();
    world.last_error = Some(err);
}

#[when(expr = "the authority registers an SPL interface for a second mint")]
fn register_second_interface(world: &mut ShieldedPoolWorld) {
    let mint_b = world.rpc().create_mint().expect("create_mint");
    let authority = world.authority().insecure_clone();
    let (registry_b, vault_b) = world
        .rpc()
        .create_spl_interface(&authority, &mint_b)
        .expect("create_spl_interface mint B");
    world.mint = Some(mint_b);
    world.spl_registry = Some(registry_b);
    world.spl_vault = Some(vault_b);
}

#[when(expr = "a non-authority registers an SPL interface for a mint")]
fn register_interface_non_authority(world: &mut ShieldedPoolWorld) {
    let mint = world.rpc().create_mint().expect("create_mint");
    let impostor = Keypair::new();
    world
        .rpc()
        .airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let err = world
        .rpc()
        .create_spl_interface(&impostor, &mint)
        .unwrap_err();
    world.last_error = Some(err);
}

// === SPL deposit setup ===

#[given(expr = "an SPL depositor holding {int} tokens")]
fn spl_depositor(world: &mut ShieldedPoolWorld, balance: u64) {
    register_spl_interface(world);
    let mint = world.mint();
    let depositor = Keypair::new();
    world
        .rpc()
        .airdrop(&depositor.pubkey(), 1_000_000_000)
        .expect("fund");
    let user_token = world
        .rpc()
        .create_token_account(&mint, &depositor.pubkey())
        .expect("token account");
    world
        .rpc()
        .mint_to(&mint, &user_token, balance)
        .expect("mint_to");
    world.depositor = Some(depositor);
    world.user_token = Some(user_token);
}

// === SPL deposit ===

#[when(expr = "the SPL depositor shields {int} tokens to a fresh recipient")]
fn spl_shield(world: &mut ShieldedPoolWorld, amount: u64) {
    let tree = world.tree().pubkey();
    let mint = world.mint();
    let user_token = world.user_token();
    let vault = world.rpc().spl_asset_vault_pda(&mint);
    let mut recipient =
        Wallet::new(ShieldedKeypair::new().expect("recipient keypair")).expect("wallet");
    let seed = [7u8; BLINDING_LEN];
    let data = ZolanaProgramTest::wallet_spl_shield_data(amount, &recipient, &seed, 0)
        .expect("wallet deposit data");

    let vault_before = world.rpc().token_balance(&vault).expect("vault balance");
    let user_token_before = world
        .rpc()
        .token_balance(&user_token)
        .expect("user token balance");
    let root_before = world.rpc().state_root(&tree).expect("root");
    let depositor = world.depositor().insecure_clone();
    let event = world
        .rpc()
        .proofless_shield_spl(&tree, &depositor, &user_token, &mint, &data)
        .expect("deposit");

    assert_spl_deposit(
        world.rpc(),
        &tree,
        &mint,
        &vault,
        &user_token,
        &event,
        &data,
        amount,
        vault_before,
        user_token_before,
        root_before,
        &mut recipient,
    );
    world.last_proofless_view = Some(event);
    world.recipient = Some(recipient);
}

#[when(expr = "the SPL depositor shields from a foreign token account")]
fn spl_shield_foreign_token(world: &mut ShieldedPoolWorld) {
    let tree = world.tree().pubkey();
    let mint = world.mint();
    let depositor = world.depositor().insecure_clone();
    let other = Keypair::new();
    let other_token = world
        .rpc()
        .create_token_account(&mint, &other.pubkey())
        .expect("token account");
    world
        .rpc()
        .mint_to(&mint, &other_token, 1_000_000)
        .expect("mint_to");
    let accounts = spl_accounts(world.rpc(), &tree, &depositor.pubkey(), &other_token, &mint);
    let err = world
        .rpc()
        .proofless_shield_with_accounts(
            accounts,
            &depositor,
            &ZolanaProgramTest::spl_shield_data(1_000, [1u8; 32]),
        )
        .unwrap_err();
    world.last_error = Some(err);
}

#[when(expr = "the SPL depositor shields through a non-canonical vault")]
fn spl_shield_non_canonical_vault(world: &mut ShieldedPoolWorld) {
    let tree = world.tree().pubkey();
    let mint = world.mint();
    let user_token = world.user_token();
    let depositor = world.depositor().insecure_clone();
    let spl_vault_authority = world.rpc().spl_vault_authority();
    let decoy_vault = world
        .rpc()
        .create_token_account(&mint, &spl_vault_authority)
        .expect("decoy vault");
    let mut accounts = spl_accounts(world.rpc(), &tree, &depositor.pubkey(), &user_token, &mint);
    accounts[3] = AccountMeta::new(decoy_vault, false);
    let err = world
        .rpc()
        .proofless_shield_with_accounts(
            accounts,
            &depositor,
            &ZolanaProgramTest::spl_shield_data(1_000, [1u8; 32]),
        )
        .unwrap_err();
    world.last_error = Some(err);
}

#[when(expr = "the SPL depositor shields with a mismatched mint")]
fn spl_shield_mint_mismatch(world: &mut ShieldedPoolWorld) {
    let tree = world.tree().pubkey();
    let mint_a = world.mint();
    let depositor = world.depositor().insecure_clone();
    let mint_b = world.rpc().create_mint().expect("mint B");
    let token_b = world
        .rpc()
        .create_token_account(&mint_b, &depositor.pubkey())
        .expect("token account");
    world
        .rpc()
        .mint_to(&mint_b, &token_b, 1_000_000)
        .expect("mint_to");
    let accounts = spl_accounts(world.rpc(), &tree, &depositor.pubkey(), &token_b, &mint_a);
    let err = world
        .rpc()
        .proofless_shield_with_accounts(
            accounts,
            &depositor,
            &ZolanaProgramTest::spl_shield_data(1_000, [1u8; 32]),
        )
        .unwrap_err();
    world.last_error = Some(err);
}

#[when(expr = "the SPL depositor shields {int} tokens it cannot afford")]
fn spl_shield_unaffordable(world: &mut ShieldedPoolWorld, amount: u64) {
    let tree = world.tree().pubkey();
    let mint = world.mint();
    let user_token = world.user_token();
    let depositor = world.depositor().insecure_clone();
    let err = world
        .rpc()
        .proofless_shield_spl(
            &tree,
            &depositor,
            &user_token,
            &mint,
            &ZolanaProgramTest::spl_shield_data(amount, [3u8; 32]),
        )
        .unwrap_err();
    world.last_error = Some(err);
}

#[then(expr = "the SPL deposit fails with insufficient token funds")]
fn rejected_token_insufficient(world: &mut ShieldedPoolWorld) {
    assert_custom(world.last_error(), TOKEN_INSUFFICIENT_FUNDS);
}
