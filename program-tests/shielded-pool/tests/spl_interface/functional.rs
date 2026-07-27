use solana_address::Address;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_interface::{instruction::UpdateProtocolConfigData, pda, state::SplAssetRegistry};
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::ZolanaProgramTest;
use zolana_test_utils::litesvm_asserts::{
    litesvm_assert_create_spl_interface, litesvm_assert_spl_deposit, SplDepositAssertArgs,
};
use zolana_transaction::{AssetRegistry, LocalWalletAuthority, Wallet};

use shielded_pool_tests::support::fixtures::{register_mint, spl_depositor, Pool};

#[test]
fn spl_interface_registration_allocates_first_stable_id() {
    let mut pool = Pool::initialized();
    let (mint_a, registry_a, vault_a) = register_mint(&mut pool);
    litesvm_assert_create_spl_interface(&pool.rpc, &registry_a, &vault_a, &mint_a, 2, 3);
    let registry_data = pool.rpc.account_data(&registry_a).expect("registry A");
    let parsed = SplAssetRegistry::from_account_bytes(&registry_data).expect("parse registry A");
    assert_eq!(parsed.mint.to_bytes(), mint_a.to_bytes());
    assert_eq!(parsed.asset_id, 2);
}

#[test]
fn spl_interface_registration_allocates_sequential_ids() {
    let mut pool = Pool::initialized();
    register_mint(&mut pool);
    let mint_b = pool.rpc.create_mint().expect("create second mint");
    let (registry_b, vault_b) = pool
        .rpc
        .create_spl_interface(&pool.authority, &mint_b)
        .expect("create second interface");
    litesvm_assert_create_spl_interface(&pool.rpc, &registry_b, &vault_b, &mint_b, 3, 4);
}

#[test]
fn spl_registries_are_discoverable_by_program_account_scan() {
    let mut pool = Pool::initialized();
    let (mint_a, _, _) = register_mint(&mut pool);
    let mint_b = pool.rpc.create_mint().expect("create second mint");
    pool.rpc
        .create_spl_interface(&pool.authority, &mint_b)
        .expect("create second interface");

    let owned_accounts = pool
        .rpc
        .get_program_accounts(Address::new_from_array(
            zolana_interface::SHIELDED_POOL_PROGRAM_ID,
        ))
        .expect("scan shielded-pool-owned accounts");
    let mut registries: Vec<_> = owned_accounts
        .iter()
        .filter_map(|(_, account)| SplAssetRegistry::from_account_bytes(&account.data).ok())
        .map(|registry| (registry.asset_id, registry.mint.to_bytes()))
        .collect();
    registries.sort_unstable_by_key(|(asset_id, _)| *asset_id);
    assert_eq!(
        registries,
        vec![(2, mint_a.to_bytes()), (3, mint_b.to_bytes())],
        "LiteSVM get_program_accounts must expose every registry for lazy wallet sync"
    );
}

#[test]
fn spl_interface_creation_changes_only_the_expected_accounts() {
    let mut pool = Pool::initialized();
    let (_, registry, vault) = register_mint(&mut pool);

    // Rent moves from the authority, the fee from the transaction fee payer,
    // and the counter advances; the mint (read-only) and every other message
    // account must be untouched.
    let trace = pool.rpc.last_transaction_trace().expect("creation trace");
    let allowed = [
        registry,
        vault,
        pda::spl_asset_counter(),
        pool.authority.pubkey(),
        pool.rpc.payer.pubkey(),
    ];
    let unexpected: Vec<Pubkey> = trace
        .changed_accounts()
        .map(|transition| transition.address)
        .filter(|address| !allowed.contains(address))
        .collect();
    assert!(
        unexpected.is_empty(),
        "creation must not touch other accounts (mint included): {unexpected:?}"
    );
}

#[test]
fn spl_interface_creation_succeeds_for_prefunded_pdas() {
    let mut pool = Pool::initialized();
    pool.rpc
        .ensure_asset_counter(&pool.authority)
        .expect("asset counter");
    let mint = pool.rpc.create_mint().expect("mint");
    // An attacker donation to either target PDA must not block creation (the
    // pinocchio helper falls back to allocate + assign + top-up).
    pool.rpc
        .airdrop(&pda::spl_asset_registry(&mint), 1_000_000)
        .expect("prefund registry PDA");
    pool.rpc
        .airdrop(&pda::spl_asset_vault(&mint), 1_000_000)
        .expect("prefund vault PDA");

    let (registry, vault) = pool
        .rpc
        .create_spl_interface(&pool.authority, &mint)
        .expect("create interface over prefunded PDAs");
    litesvm_assert_create_spl_interface(&pool.rpc, &registry, &vault, &mint, 2, 3);
}

#[test]
fn permissionless_spl_interface_creation_accepts_outsider() {
    let mut pool = Pool::initialized();
    pool.rpc
        .ensure_asset_counter(&pool.authority)
        .expect("asset counter");
    let mint = pool.rpc.create_mint().expect("mint");
    let outsider = pool.funded_signer(1_000_000_000);
    pool.rpc
        .send_protocol_config_update(
            &pool.authority,
            UpdateProtocolConfigData::SplInterfaceCreationPermissionless(true),
        )
        .expect("enable permissionless SPL interfaces");

    let (registry, vault) = pool
        .rpc
        .create_spl_interface(&outsider, &mint)
        .expect("permissionless interface creation");
    litesvm_assert_create_spl_interface(&pool.rpc, &registry, &vault, &mint, 2, 3);
}

#[test]
fn spl_deposit_moves_tokens_emits_the_exact_output_and_updates_the_indexer() {
    let mut pool = Pool::initialized();
    let (mint, _, vault) = register_mint(&mut pool);
    let (depositor, user_token) = spl_depositor(&mut pool, mint, 1_000_000);
    let recipient_key = ShieldedKeypair::new().expect("recipient keypair");
    let mut recipient = Wallet::new(
        recipient_key.shielded_address().expect("shielded address"),
        AssetRegistry::default(),
    )
    .expect("recipient wallet");
    let data = ZolanaProgramTest::wallet_spl_shield_data(
        400_000,
        &recipient.identity,
        &[7u8; 32],
        0,
        &mint,
        &user_token,
    )
    .expect("SPL deposit data");
    let tree = pool.tree.pubkey();
    let root_before = pool.rpc.state_root(&tree).expect("root");
    let vault_before = pool.rpc.token_balance(&vault).expect("vault balance");
    let user_before = pool
        .rpc
        .token_balance(&user_token)
        .expect("user token balance");

    let event = pool
        .rpc
        .deposit(&tree, &depositor, &data)
        .expect("SPL deposit");
    litesvm_assert_spl_deposit(
        &mut pool.rpc,
        &mut recipient,
        SplDepositAssertArgs {
            tree: &tree,
            mint: &mint,
            vault: &vault,
            user_token: &user_token,
            event: &event,
            data: &data,
            expected_amount: 400_000,
            vault_before,
            user_token_before: user_before,
            root_before,
            authority: &LocalWalletAuthority::new(Address::default(), &recipient_key),
        },
    );
    assert_eq!(recipient.utxos.len(), 1);
}
