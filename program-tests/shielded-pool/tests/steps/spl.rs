//! SPL asset registration and SPL-deposit settlement steps.

use cucumber::{given, then, when};
use solana_instruction::AccountMeta;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_address::Address;
use zolana_client::Rpc;
use zolana_interface::{pda, state::SplAssetRegistry, PROGRAM_ID_PUBKEY, SHIELDED_POOL_PROGRAM_ID};
use zolana_keypair::{constants::BLINDING_LEN, ShieldedKeypair};
use zolana_program_test::ZolanaProgramTest;
use zolana_test_utils::litesvm_asserts::{
    litesvm_assert_create_spl_interface, litesvm_assert_spl_deposit,
};
use zolana_transaction::{AssetRegistry, Wallet};

use crate::{common::assert_custom, ShieldedPoolWorld};

const TOKEN_INSUFFICIENT_FUNDS: u32 = 1;

fn spl_accounts(
    tree: &Pubkey,
    depositor: &Pubkey,
    user_token: &Pubkey,
    mint: &Pubkey,
) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(*tree, false),
        AccountMeta::new(*depositor, true),
        AccountMeta::new(*user_token, false),
        AccountMeta::new(pda::spl_asset_vault(mint), false),
        AccountMeta::new_readonly(pda::spl_asset_registry(mint), false),
        AccountMeta::new_readonly(ZolanaProgramTest::token_program_id(), false),
        AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
    ]
}

// === SPL interface registration ===

#[given(expr = "a registered mint")]
#[when(expr = "the authority registers an SPL interface for a mint")]
fn register_spl_interface(world: &mut ShieldedPoolWorld) {
    let mint = world.rpc().create_mint().expect("create_mint");
    let authority = world.authority().insecure_clone();
    world
        .rpc()
        .ensure_asset_counter(&authority)
        .expect("create_asset_counter");
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
    litesvm_assert_create_spl_interface(rpc, &registry, &vault, &mint, registry_index, vault_index);
}

#[then(expr = "the on-chain asset registry resolves the mint to id {int}")]
fn assert_registry_resolvable_from_chain(world: &mut ShieldedPoolWorld, expected_asset_id: u64) {
    // Exercise the real get_program_accounts + SplAssetRegistry::from_account_bytes
    // path the client's lazy sync-refresh relies on: scan the shielded-pool
    // program's accounts, parse each registry record, and confirm the mint the
    // scenario just registered resolves to its assigned asset id.
    let mint = world.mint();
    let program_id = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let accounts = world
        .rpc_ref()
        .get_program_accounts(program_id)
        .expect("get_program_accounts");

    let resolved = accounts.iter().find_map(|(_, account)| {
        let registry = SplAssetRegistry::from_account_bytes(&account.data).ok()?;
        (registry.mint.to_bytes() == mint.to_bytes()).then_some(registry.asset_id)
    });

    assert_eq!(
        resolved,
        Some(expected_asset_id),
        "registered mint should resolve to its asset id via on-chain scan"
    );
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
    world
        .rpc()
        .ensure_asset_counter(&authority)
        .expect("create_asset_counter");
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
    let authority = world.authority().insecure_clone();
    world
        .rpc()
        .ensure_asset_counter(&authority)
        .expect("create_asset_counter");
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
    let vault = pda::spl_asset_vault(&mint);
    let mut recipient = Wallet::new(
        ShieldedKeypair::new().expect("recipient keypair"),
        AssetRegistry::default(),
    )
    .expect("wallet");
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
        .deposit_spl(&tree, &depositor, &user_token, &mint, &data)
        .expect("deposit");

    litesvm_assert_spl_deposit(
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
    let accounts = spl_accounts(&tree, &depositor.pubkey(), &other_token, &mint);
    let err = world
        .rpc()
        .deposit_with_accounts(
            accounts,
            &depositor,
            &ZolanaProgramTest::spl_shield_data(1_000, [1u8; 32], [1u8; 31]),
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
    let spl_vault_authority = pda::shielded_pool_cpi_authority();
    let decoy_vault = world
        .rpc()
        .create_token_account(&mint, &spl_vault_authority)
        .expect("decoy vault");
    let mut accounts = spl_accounts(&tree, &depositor.pubkey(), &user_token, &mint);
    accounts[3] = AccountMeta::new(decoy_vault, false);
    let err = world
        .rpc()
        .deposit_with_accounts(
            accounts,
            &depositor,
            &ZolanaProgramTest::spl_shield_data(1_000, [1u8; 32], [1u8; 31]),
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
    let accounts = spl_accounts(&tree, &depositor.pubkey(), &token_b, &mint_a);
    let err = world
        .rpc()
        .deposit_with_accounts(
            accounts,
            &depositor,
            &ZolanaProgramTest::spl_shield_data(1_000, [1u8; 32], [1u8; 31]),
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
        .deposit_spl(
            &tree,
            &depositor,
            &user_token,
            &mint,
            &ZolanaProgramTest::spl_shield_data(amount, [3u8; 32], [3u8; 31]),
        )
        .unwrap_err();
    world.last_error = Some(err);
}

#[then(expr = "the SPL deposit fails with insufficient token funds")]
fn rejected_token_insufficient(world: &mut ShieldedPoolWorld) {
    assert_custom(world.last_error(), TOKEN_INSUFFICIENT_FUNDS);
}
