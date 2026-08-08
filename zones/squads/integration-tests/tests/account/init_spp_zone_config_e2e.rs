//! On-chain test for `init_spp_zone_config` (tag 16) against a real SPP
//! program loaded into the same LiteSVM instance. The zone-auth-signed CPI
//! must create SPP's `zone_config` account, at the same address as this
//! program's own `ring_auth` PDA, with the expected owner, discriminator,
//! and fields.
//!
//! Tests skip when either prebuilt `.so` is missing.

use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_zone_tests::{custom_code, default_spp_program_path, SquadsZoneTest};
use zolana_interface::{
    state::{
        discriminator::RING_CONFIG as SPP_ZONE_CONFIG_DISCRIMINATOR, ProtocolConfig, RingConfig,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_squads_interface::{
    error::SquadsZoneError,
    instruction::{
        builders::{CreateZoneConfig, InitSppZoneConfig},
        CreateZoneConfigIxData,
    },
    RING_AUTH_PDA_SEED, SQUADS_ZONE_PROGRAM_ID, ZONE_CONFIG_PDA_SEED,
};

fn zone_config_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[ZONE_CONFIG_PDA_SEED], program_id).0
}

fn ring_auth_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[RING_AUTH_PDA_SEED], program_id).0
}

fn spp_program_id() -> Pubkey {
    Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID)
}

fn spp_protocol_config_pda() -> Pubkey {
    Pubkey::find_program_address(&[b"protocol_config"], &spp_program_id()).0
}

fn boot_with_spp() -> SquadsZoneTest {
    let mut test = SquadsZoneTest::new().expect("boot");
    test.add_program(&spp_program_id(), &default_spp_program_path())
        .expect("add SPP program");
    test
}

/// `ring_creation_is_permissionless` is set so the CPI authority check
/// passes regardless of who signs.
fn install_spp_protocol_config(test: &mut SquadsZoneTest) -> Pubkey {
    let config = ProtocolConfig {
        discriminator: zolana_interface::state::discriminator::PROTOCOL_CONFIG,
        protocol_authority: Default::default(),
        tree_creation_authority: Default::default(),
        forester_authority: Default::default(),
        ring_creation_authority: Default::default(),
        tree_creation_is_permissionless: 0,
        ring_creation_is_permissionless: 1,
        spl_interface_creation_is_permissionless: 0,
    };
    let address = spp_protocol_config_pda();
    test.set_account_with_owner(
        &address,
        bytemuck::bytes_of(&config).to_vec(),
        spp_program_id(),
    )
    .expect("install SPP protocol_config");
    address
}

fn create_squads_zone_config(test: &mut SquadsZoneTest, authority: &Pubkey) -> Pubkey {
    let creator = Keypair::new();
    test.airdrop(&creator.pubkey(), 1_000_000_000)
        .expect("fund creator");
    // create_zone_config accepts only the deploy upgrade authority.
    test.install_upgradeable_deploy(Some(&creator.pubkey()))
        .expect("install upgradeable deploy");
    let zone_config = zone_config_pda(&test.program_id);
    let ix = CreateZoneConfig {
        creator: creator.pubkey(),
        zone_config,
        system_program: Pubkey::default(),
        data: CreateZoneConfigIxData {
            authority: *authority,
            co_signer: Pubkey::default(),
            max_proposal_lifetime: 3_600,
            auditor_keys: vec![[9u8; 33]],
            merge_authorities: vec![],
        },
    }
    .instruction();
    test.send(&[ix], &[&creator]).expect("create_zone_config");
    zone_config
}

#[test]
fn init_spp_zone_config_happy_path() {
    let mut test = boot_with_spp();
    let protocol_config = install_spp_protocol_config(&mut test);

    let authority = Keypair::new();
    test.airdrop(&authority.pubkey(), 1_000_000_000)
        .expect("fund authority");
    let squads_zone_config = create_squads_zone_config(&mut test, &authority.pubkey());
    let ring_auth = ring_auth_pda(&test.program_id);

    let ix = InitSppZoneConfig {
        authority: authority.pubkey(),
        zone_config: squads_zone_config,
        protocol_config,
        ring_auth,
        system_program: Pubkey::default(),
        spp_program: spp_program_id(),
    }
    .instruction();
    test.send(&[ix], &[&authority])
        .expect("init_spp_zone_config must succeed against a real SPP");

    let account = test.svm.get_account(&ring_auth).expect("account exists");
    assert_eq!(account.owner, spp_program_id());
    let config: RingConfig = *bytemuck::from_bytes(&account.data);
    let (_, ring_auth_bump) = Pubkey::find_program_address(&[RING_AUTH_PDA_SEED], &test.program_id);
    let expected = RingConfig {
        discriminator: SPP_ZONE_CONFIG_DISCRIMINATOR,
        authority: Address::new_from_array(authority.pubkey().to_bytes()),
        program_id: Address::new_from_array(SQUADS_ZONE_PROGRAM_ID),
        ring_authority_transact_is_enabled: 1,
        paused: 0,
        bump: ring_auth_bump,
    };
    assert_eq!(config, expected);
}

#[test]
fn init_spp_zone_config_rejects_wrong_authority() {
    let mut test = boot_with_spp();
    let protocol_config = install_spp_protocol_config(&mut test);

    let authority = Keypair::new();
    let impostor = Keypair::new();
    test.airdrop(&authority.pubkey(), 1_000_000_000)
        .expect("fund authority");
    test.airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund impostor");
    let squads_zone_config = create_squads_zone_config(&mut test, &authority.pubkey());
    let ring_auth = ring_auth_pda(&test.program_id);

    let ix = InitSppZoneConfig {
        authority: impostor.pubkey(),
        zone_config: squads_zone_config,
        protocol_config,
        ring_auth,
        system_program: Pubkey::default(),
        spp_program: spp_program_id(),
    }
    .instruction();
    let err = test
        .send(&[ix], &[&impostor])
        .expect_err("expected AuthorityMismatch");
    assert_eq!(custom_code(&err), SquadsZoneError::AuthorityMismatch as u32);
}
