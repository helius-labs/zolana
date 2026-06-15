//! Zone-config admin coverage.

mod common;

use common::{assert_pool_error, program_test};
use shielded_pool_program::error::ShieldedPoolError;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{encode_instruction, tag, CreateZoneConfigData},
    state::{discriminator::ZONE_CONFIG, ZoneConfig},
};
use zolana_program_test::ZONE_TEST_PROGRAM_ID;

#[derive(Debug, PartialEq, Eq)]
struct ZoneConfigState {
    authority: Pubkey,
    zone_authority_transact_is_enabled: bool,
    bump: u8,
}

#[test]
fn create_and_update_zone_config() {
    let Some(mut program_test) = program_test() else {
        return;
    };
    if program_test.load_zone_test_program().is_err() {
        eprintln!("skipping: zone_test_program.so missing");
        return;
    }

    let payer = Keypair::new();
    program_test
        .airdrop(&payer.pubkey(), 1_000_000_000)
        .expect("fund payer");
    let authority = Keypair::new();
    let zone_config = program_test
        .create_zone_config(&payer, &authority.pubkey(), true)
        .expect("create_zone_config");

    let state = read_zone_config(
        &program_test
            .account_data(&zone_config)
            .expect("zone config exists"),
    );
    assert_eq!(
        state,
        ZoneConfigState {
            authority: authority.pubkey(),
            zone_authority_transact_is_enabled: true,
            bump: program_test
                .zone_config_pda(&Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID))
                .1,
        }
    );

    program_test
        .update_zone_config(&authority, &zone_config, false)
        .expect("disable zone authority transact");
    let state = read_zone_config(
        &program_test
            .account_data(&zone_config)
            .expect("zone config exists"),
    );
    assert_eq!(state.authority, authority.pubkey());
    assert!(!state.zone_authority_transact_is_enabled);

    let next = Keypair::new();
    program_test
        .update_zone_config_owner(&authority, &zone_config, &next.pubkey())
        .expect("rotate owner");
    let state = read_zone_config(
        &program_test
            .account_data(&zone_config)
            .expect("zone config exists"),
    );
    assert_eq!(state.authority, next.pubkey());

    let err = program_test
        .update_zone_config(&authority, &zone_config, true)
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
    program_test
        .update_zone_config(&next, &zone_config, true)
        .expect("new owner can update");
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

#[test]
fn create_zone_config_rejects_fake_zone_auth() {
    let Some(mut program_test) = program_test() else {
        return;
    };
    let payer = Keypair::new();
    program_test
        .airdrop(&payer.pubkey(), 1_000_000_000)
        .expect("fund payer");
    let zone_program = Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID);
    let (zone_config, zone_config_bump) = program_test.zone_config_pda(&zone_program);
    let (_, zone_auth_bump) = program_test.zone_auth_pda();
    let data = CreateZoneConfigData {
        program_id: ZONE_TEST_PROGRAM_ID,
        zone_auth_bump,
        authority: payer.pubkey().to_bytes(),
        zone_authority_transact_is_enabled: true,
        zone_config_bump,
    };
    let ix = Instruction {
        program_id: program_test.program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(zone_config, false),
            AccountMeta::new_readonly(payer.pubkey(), true),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ],
        data: encode_instruction(tag::CREATE_ZONE_CONFIG, &data),
    };
    let err = program_test
        .create_and_send_default_payer_transaction(&[ix], &[&payer])
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidZoneConfig);
}
