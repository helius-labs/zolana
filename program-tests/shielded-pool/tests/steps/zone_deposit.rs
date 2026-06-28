//! Policy-zone proofless deposit steps.

use cucumber::when;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{instruction::ZoneDeposit, pda};
use zolana_keypair::{constants::BLINDING_LEN, ShieldedKeypair};
use zolana_program_test::ZONE_TEST_PROGRAM_ID;
use zolana_test_utils::litesvm_asserts::litesvm_assert_zone_deposit;
use zolana_transaction::Wallet;

use crate::ShieldedPoolWorld;

#[when(expr = "the depositor zone-shields {int} lamports to a fresh recipient")]
fn zone_shield(world: &mut ShieldedPoolWorld, amount: u64) {
    world
        .rpc()
        .load_zone_test_program()
        .expect("zone_test_program.so must be built");
    // The deposit loads the zone's `ZoneConfig` account, so it must be registered
    // first. The protocol-config authority is the zone-creation authority.
    let zone_authority = world.authority().insecure_clone();
    world
        .rpc()
        .create_zone_config(&zone_authority, &zone_authority.pubkey(), true)
        .expect("create zone config");

    let tree = world.tree().pubkey();
    let depositor = Keypair::new();
    world
        .rpc()
        .airdrop(&depositor.pubkey(), 5_000_000_000)
        .expect("fund");
    let mut recipient =
        Wallet::new(ShieldedKeypair::new().expect("recipient keypair")).expect("wallet");

    let seed = [5u8; BLINDING_LEN];
    let mut data = world
        .rpc()
        .wallet_zone_sol_shield_data(amount, &recipient, &seed, 0)
        .expect("wallet zone deposit data");
    data.zone_data_hash = [5u8; 32];

    let root_before = world.rpc().state_root(&tree).expect("root");
    let event = world
        .rpc()
        .zone_deposit(&tree, &depositor, &data)
        .expect("zone deposit");

    litesvm_assert_zone_deposit(
        world.rpc(),
        &tree,
        &event,
        &data,
        amount,
        [0u8; 32],
        ZONE_TEST_PROGRAM_ID,
        root_before,
        &mut recipient,
    );
    world.depositor = Some(depositor);
    world.last_proofless_view = Some(event);
    world.recipient = Some(recipient);
}

#[when(expr = "the SPL depositor zone-shields {int} tokens to a fresh recipient")]
fn zone_spl_shield(world: &mut ShieldedPoolWorld, amount: u64) {
    world
        .rpc()
        .load_zone_test_program()
        .expect("zone_test_program.so must be built");
    let zone_authority = world.authority().insecure_clone();
    world
        .rpc()
        .create_zone_config(&zone_authority, &zone_authority.pubkey(), true)
        .expect("create zone config");

    let tree = world.tree().pubkey();
    let mint = world.mint();
    let user_token = world.user_token();
    let vault = pda::spl_asset_vault(&mint);
    let depositor = world.depositor().insecure_clone();
    let mut recipient =
        Wallet::new(ShieldedKeypair::new().expect("recipient keypair")).expect("wallet");

    let seed = [9u8; BLINDING_LEN];
    let mut data = world
        .rpc()
        .wallet_zone_spl_shield_data(amount, &recipient, &seed, 0)
        .expect("wallet zone SPL deposit data");
    data.zone_data_hash = [9u8; 32];

    let vault_before = world.rpc().token_balance(&vault).expect("vault balance");
    let user_token_before = world
        .rpc()
        .token_balance(&user_token)
        .expect("user token balance");
    let root_before = world.rpc().state_root(&tree).expect("root");
    let event = world
        .rpc()
        .zone_deposit_spl(&tree, &depositor, &user_token, &mint, &data)
        .expect("zone SPL deposit");

    assert_eq!(
        world.rpc().token_balance(&vault),
        Some(vault_before + amount),
        "vault grows by the deposit"
    );
    assert_eq!(
        world.rpc().token_balance(&user_token),
        Some(user_token_before - amount),
        "user token account shrinks by the deposit"
    );
    litesvm_assert_zone_deposit(
        world.rpc(),
        &tree,
        &event,
        &data,
        amount,
        mint.to_bytes(),
        ZONE_TEST_PROGRAM_ID,
        root_before,
        &mut recipient,
    );
    world.depositor = Some(depositor);
    world.last_proofless_view = Some(event);
    world.recipient = Some(recipient);
}

#[when(expr = "a zone proofless deposit is sent straight to the pool with the wrong signer")]
fn zone_shield_wrong_signer(world: &mut ShieldedPoolWorld) {
    let tree = world.tree().pubkey();
    let depositor = Keypair::new();
    world
        .rpc()
        .airdrop(&depositor.pubkey(), 5_000_000_000)
        .expect("fund");

    let data = world
        .rpc()
        .zone_sol_shield_data(1_000_000, [3u8; 32], [4u8; 31]);
    let mut ix = ZoneDeposit {
        tree,
        depositor: depositor.pubkey(),
        spl: None,
        view_tag: data.view_tag,
        owner: data.owner,
        blinding: data.blinding,
        public_amount: data.public_amount,
        zone_program_id: Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID),
        zone_data_hash: data.zone_data_hash,
        zone_data: data.zone_data.clone(),
        program: data.program.clone(),
    }
    .cpi_instruction()
    .expect("zone auth PDA");
    if let Some(meta) = ix.accounts.get_mut(2) {
        meta.pubkey = depositor.pubkey();
    }
    let err = world
        .rpc()
        .create_and_send_default_payer_transaction(&[ix], &[&depositor])
        .unwrap_err();
    world.last_error = Some(err);
}
