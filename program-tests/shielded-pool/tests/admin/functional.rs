use mollusk_svm::result::Check;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::UpdateProtocolConfigData,
    pda,
    state::{discriminator::ZONE_CONFIG, ProtocolConfig, ZoneConfig},
};
use zolana_program_test::{ZolanaProgramTest, ZONE_TEST_PROGRAM_ID};
use zolana_test_utils::litesvm_asserts::litesvm_assert_protocol_config;

use crate::{
    common::{program_test, tree_account_size},
    mollusk::{pause_tree_fixture, protocol_config_fixture},
    support::Pool,
};

#[derive(Debug, PartialEq, Eq)]
struct ZoneConfigState {
    authority: Pubkey,
    enabled: bool,
    bump: u8,
}

fn read_zone_config(rpc: &ZolanaProgramTest, address: &Pubkey) -> ZoneConfigState {
    let bytes = rpc.account_data(address).expect("zone config account");
    assert_eq!(bytes.len(), ZoneConfig::SIZE);
    assert_eq!(bytes.first(), Some(&ZONE_CONFIG));
    let config: &ZoneConfig = bytemuck::from_bytes(&bytes);
    ZoneConfigState {
        authority: Pubkey::new_from_array(config.authority.to_bytes()),
        enabled: config.enabled(),
        bump: config.bump,
    }
}

#[test]
fn protocol_config_creation_initializes_complete_state() {
    let mut rpc = program_test();
    let authority = Keypair::new();
    let config = rpc
        .create_protocol_config(&authority)
        .expect("create protocol config");
    litesvm_assert_protocol_config(&rpc, &config, &authority.pubkey());
}

#[test]
fn protocol_config_fixture_executes_successfully_before_mutation() {
    let (mollusk, instruction, accounts) = protocol_config_fixture();
    mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);
}

#[test]
fn pause_tree_fixture_executes_successfully_before_mutation() {
    let (mollusk, instruction, accounts) = pause_tree_fixture();
    mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);
}

#[test]
fn protocol_authority_rotation_updates_all_authority_fields() {
    let mut pool = Pool::initialized();
    let old = pool.authority.insecure_clone();
    let next = pool.funded_signer(1_000_000_000);
    pool.rpc
        .update_protocol_config(&old, &next)
        .expect("rotate protocol authorities");

    let config_data = pool
        .rpc
        .account_data(&pda::protocol_config())
        .expect("protocol config");
    let config: &ProtocolConfig = bytemuck::from_bytes(&config_data);
    for authority in [
        config.protocol_authority,
        config.tree_creation_authority,
        config.forester_authority,
        config.zone_creation_authority,
    ] {
        assert_eq!(authority.to_bytes(), next.pubkey().to_bytes());
    }
}

#[test]
fn new_protocol_authority_can_update_config() {
    let mut pool = Pool::initialized();
    let old = pool.authority.insecure_clone();
    let next = pool.funded_signer(1_000_000_000);
    pool.rpc
        .update_protocol_config(&old, &next)
        .expect("rotate protocol authorities");

    pool.rpc
        .send_protocol_config_update(
            &next,
            UpdateProtocolConfigData::TreeCreationPermissionless(true),
        )
        .expect("new authority updates config");
}

#[test]
fn new_tree_creation_authority_can_create_tree() {
    let mut pool = Pool::initialized();
    let old = pool.authority.insecure_clone();
    let next = pool.funded_signer(1_000_000_000);
    pool.rpc
        .update_protocol_config(&old, &next)
        .expect("rotate protocol authorities");
    pool.rpc
        .send_protocol_config_update(
            &next,
            UpdateProtocolConfigData::TreeCreationPermissionless(true),
        )
        .expect("new authority updates config");

    pool.rpc
        .create_tree(tree_account_size(), &next)
        .expect("new authority creates tree");
}

#[test]
fn zone_config_creation_initializes_complete_state() {
    let mut rpc = program_test();
    rpc.load_zone_test_program()
        .expect("load zone test program");
    let admin = Keypair::new();
    rpc.create_protocol_config_permissionless(&admin)
        .expect("create permissionless protocol config");
    let payer = Keypair::new();
    rpc.airdrop(&payer.pubkey(), 1_000_000_000)
        .expect("fund payer");
    let authority = Keypair::new();

    let zone_config = rpc
        .create_zone_config(&payer, &authority.pubkey(), true)
        .expect("create zone config");
    assert_eq!(
        read_zone_config(&rpc, &zone_config),
        ZoneConfigState {
            authority: authority.pubkey(),
            enabled: true,
            bump: pda::zone_auth(&Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID)).1,
        }
    );
}

#[test]
fn zone_config_update_changes_enabled_state() {
    let mut rpc = program_test();
    rpc.load_zone_test_program()
        .expect("load zone test program");
    let admin = Keypair::new();
    rpc.create_protocol_config_permissionless(&admin)
        .expect("create permissionless protocol config");
    let payer = Keypair::new();
    rpc.airdrop(&payer.pubkey(), 1_000_000_000)
        .expect("fund payer");
    let authority = Keypair::new();
    let zone_config = rpc
        .create_zone_config(&payer, &authority.pubkey(), true)
        .expect("create zone config");

    rpc.update_zone_config(&authority, &zone_config, false)
        .expect("disable zone authority transact");
    assert_eq!(
        read_zone_config(&rpc, &zone_config),
        ZoneConfigState {
            authority: authority.pubkey(),
            enabled: false,
            bump: pda::zone_auth(&Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID)).1,
        }
    );
}

#[test]
fn zone_config_owner_rotation_updates_authority() {
    let mut rpc = program_test();
    rpc.load_zone_test_program()
        .expect("load zone test program");
    let admin = Keypair::new();
    rpc.create_protocol_config_permissionless(&admin)
        .expect("create permissionless protocol config");
    let payer = Keypair::new();
    rpc.airdrop(&payer.pubkey(), 1_000_000_000)
        .expect("fund payer");
    let authority = Keypair::new();
    let zone_config = rpc
        .create_zone_config(&payer, &authority.pubkey(), true)
        .expect("create zone config");
    rpc.update_zone_config(&authority, &zone_config, false)
        .expect("disable zone authority transact");

    let next = Keypair::new();
    rpc.update_zone_config_owner(&authority, &zone_config, &next)
        .expect("rotate zone config owner");
    assert_eq!(
        read_zone_config(&rpc, &zone_config).authority,
        next.pubkey()
    );
}

#[test]
fn new_zone_config_authority_can_update_config() {
    let mut rpc = program_test();
    rpc.load_zone_test_program()
        .expect("load zone test program");
    let admin = Keypair::new();
    rpc.create_protocol_config_permissionless(&admin)
        .expect("create permissionless protocol config");
    let payer = Keypair::new();
    rpc.airdrop(&payer.pubkey(), 1_000_000_000)
        .expect("fund payer");
    let authority = Keypair::new();
    let zone_config = rpc
        .create_zone_config(&payer, &authority.pubkey(), true)
        .expect("create zone config");
    rpc.update_zone_config(&authority, &zone_config, false)
        .expect("disable zone authority transact");
    let next = Keypair::new();
    rpc.update_zone_config_owner(&authority, &zone_config, &next)
        .expect("rotate zone config owner");

    rpc.update_zone_config(&next, &zone_config, true)
        .expect("new zone authority updates config");
    assert!(read_zone_config(&rpc, &zone_config).enabled);
}
