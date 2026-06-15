//! Zone-config admin steps.

use cucumber::{given, then, when};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{create_zone_config as create_zone_config_ix, CreateZoneConfigData},
    state::{discriminator::ZONE_CONFIG, ZoneConfig},
};
use zolana_program_test::ZONE_TEST_PROGRAM_ID;

use crate::common::assert_pool_error;
use crate::ShieldedPoolWorld;

use shielded_pool_program::error::ShieldedPoolError;

#[derive(Debug, PartialEq, Eq)]
struct ZoneConfigState {
    authority: Pubkey,
    zone_authority_transact_is_enabled: bool,
    bump: u8,
}

fn read_zone_config(bytes: &[u8]) -> ZoneConfigState {
    assert_eq!(bytes.len(), ZoneConfig::SIZE);
    assert_eq!(bytes[0], ZONE_CONFIG);

    let cfg: &ZoneConfig = bytemuck::from_bytes(bytes);
    ZoneConfigState {
        authority: Pubkey::new_from_array(cfg.authority),
        zone_authority_transact_is_enabled: cfg.enabled(),
        bump: cfg.bump,
    }
}

fn current_zone_state(world: &mut ShieldedPoolWorld) -> ZoneConfigState {
    let zone_config = world.zone_config.expect("zone config created");
    let bytes = world
        .rpc()
        .account_data(&zone_config)
        .expect("zone config exists");
    read_zone_config(&bytes)
}

#[given(expr = "the zone test program is loaded")]
fn load_zone_program(world: &mut ShieldedPoolWorld) {
    world
        .rpc()
        .load_zone_test_program()
        .expect("zone_test_program.so must be built");
}

#[given(expr = "a funded payer")]
fn funded_payer(world: &mut ShieldedPoolWorld) {
    let payer = Keypair::new();
    world
        .rpc()
        .airdrop(&payer.pubkey(), 1_000_000_000)
        .expect("fund payer");
    world.depositor = Some(payer);
}

#[when(expr = "the payer creates an enabled zone config")]
fn create_zone_config(world: &mut ShieldedPoolWorld) {
    let payer = world.depositor().insecure_clone();
    let authority = Keypair::new();
    let zone_config = world
        .rpc()
        .create_zone_config(&payer, &authority.pubkey(), true)
        .expect("create_zone_config");
    world.zone_config = Some(zone_config);
    world.zone_authority = Some(authority);
}

#[then(expr = "the zone config is owned by the authority and enabled")]
fn assert_zone_created(world: &mut ShieldedPoolWorld) {
    let expected_bump = world
        .rpc()
        .zone_config_pda(&Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID))
        .1;
    let authority = world.zone_authority.as_ref().expect("authority").pubkey();
    let state = current_zone_state(world);
    assert_eq!(
        state,
        ZoneConfigState {
            authority,
            zone_authority_transact_is_enabled: true,
            bump: expected_bump,
        }
    );
}

#[when(expr = "the authority disables zone authority transact")]
fn disable_zone(world: &mut ShieldedPoolWorld) {
    let authority = world
        .zone_authority
        .as_ref()
        .expect("authority")
        .insecure_clone();
    let zone_config = world.zone_config.expect("zone config created");
    world
        .rpc()
        .update_zone_config(&authority, &zone_config, false)
        .expect("disable zone authority transact");
}

#[then(expr = "the zone config is disabled and still owned by the authority")]
fn assert_zone_disabled(world: &mut ShieldedPoolWorld) {
    let authority = world.zone_authority.as_ref().expect("authority").pubkey();
    let state = current_zone_state(world);
    assert_eq!(state.authority, authority);
    assert!(!state.zone_authority_transact_is_enabled);
}

#[when(expr = "the authority rotates the zone config owner")]
fn rotate_zone_owner(world: &mut ShieldedPoolWorld) {
    let authority = world
        .zone_authority
        .as_ref()
        .expect("authority")
        .insecure_clone();
    let zone_config = world.zone_config.expect("zone config created");
    let next = Keypair::new();
    world
        .rpc()
        .update_zone_config_owner(&authority, &zone_config, &next.pubkey())
        .expect("rotate owner");
    world.previous_zone_authority = Some(authority);
    world.zone_authority = Some(next);
}

#[then(expr = "the zone config is owned by the new owner")]
fn assert_zone_new_owner(world: &mut ShieldedPoolWorld) {
    let next = world.zone_authority.as_ref().expect("authority").pubkey();
    let state = current_zone_state(world);
    assert_eq!(state.authority, next);
}

#[when(expr = "the old owner tries to update the zone config")]
fn old_owner_updates(world: &mut ShieldedPoolWorld) {
    let stale = world
        .previous_zone_authority
        .as_ref()
        .expect("prior owner")
        .insecure_clone();
    let zone_config = world.zone_config.expect("zone config created");
    let err = world
        .rpc()
        .update_zone_config(&stale, &zone_config, true)
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
}

#[then(expr = "the new owner can update the zone config")]
fn new_owner_updates(world: &mut ShieldedPoolWorld) {
    let next = world
        .zone_authority
        .as_ref()
        .expect("authority")
        .insecure_clone();
    let zone_config = world.zone_config.expect("zone config created");
    world
        .rpc()
        .update_zone_config(&next, &zone_config, true)
        .expect("new owner can update");
}

#[when(expr = "a payer tries to create a zone config with an invalid zone authority")]
fn create_zone_config_invalid_auth(world: &mut ShieldedPoolWorld) {
    let payer = world.depositor().insecure_clone();
    let program_id = world.rpc().program_id;
    let zone_program = Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID);
    let (zone_config, zone_config_bump) = world.rpc().zone_config_pda(&zone_program);
    let (_, zone_auth_bump) = world.rpc().zone_auth_pda();
    let mut ix = create_zone_config_ix(
        payer.pubkey(),
        zone_config,
        payer.pubkey(),
        CreateZoneConfigData {
            program_id: ZONE_TEST_PROGRAM_ID,
            zone_auth_bump,
            authority: payer.pubkey().to_bytes(),
            zone_authority_transact_is_enabled: true,
            zone_config_bump,
        },
    );
    ix.program_id = program_id;
    let err = world
        .rpc()
        .create_and_send_default_payer_transaction(&[ix], &[&payer])
        .unwrap_err();
    world.last_error = Some(err);
}
