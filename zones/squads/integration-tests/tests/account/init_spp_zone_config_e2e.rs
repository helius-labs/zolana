//! End-to-end on-chain test for `init_spp_zone_config` (tag 16): the zone's
//! first real CPI into a REAL SPP program loaded into the same LiteSVM
//! instance. Confirms the zone-auth-signed CPI creates SPP's `zone_config`
//! account (identical address to this program's own `zone_auth` PDA) with
//! the expected owner, discriminator, and fields.
//!
//! GATING: requires both prebuilt binaries (skips if either is missing).
//! Build them first:
//!   cd zones/squads/program && cargo build-sbf --features bpf-entrypoint
//!   just build-programs   (from the repo root, builds the SPP .so)
//! Run with:
//!   cargo test --manifest-path zones/squads/Cargo.toml -p squads-zone-tests --test init_spp_zone_config_e2e -- --nocapture

use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_zone_tests::{custom_code, default_spp_program_path, SquadsZoneTest};
use zolana_interface::{
    state::{
        discriminator::ZONE_CONFIG as SPP_ZONE_CONFIG_DISCRIMINATOR, ProtocolConfig, ZoneConfig,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_squads_interface::{
    error::SquadsZoneError,
    instruction::{
        builders::{CreateZoneConfig, InitSppZoneConfig},
        CreateZoneConfigIxData,
    },
    SQUADS_ZONE_PROGRAM_ID, ZONE_AUTH_PDA_SEED, ZONE_CONFIG_PDA_SEED,
};

fn zone_config_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[ZONE_CONFIG_PDA_SEED], program_id).0
}

fn zone_auth_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[ZONE_AUTH_PDA_SEED], program_id).0
}

fn spp_program_id() -> Pubkey {
    Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID)
}

fn spp_protocol_config_pda() -> Pubkey {
    Pubkey::find_program_address(&[b"protocol_config"], &spp_program_id()).0
}

/// Boot LiteSVM with both the squads zone program and a REAL SPP program;
/// returns `None` (clean skip) if either `.so` is missing.
fn boot_with_spp() -> Option<SquadsZoneTest> {
    let mut test = SquadsZoneTest::new().expect("boot")?;
    let loaded = test
        .add_program(&spp_program_id(), &default_spp_program_path())
        .expect("add SPP program");
    if !loaded {
        eprintln!("skipping init_spp_zone_config_e2e: SPP .so missing - run `just build-programs`");
        return None;
    }
    Some(test)
}

/// Install SPP's `ProtocolConfig` directly (bypassing its own create
/// instruction) with `zone_creation_is_permissionless` set, so the CPI's
/// authority check passes regardless of who signs.
fn install_spp_protocol_config(test: &mut SquadsZoneTest) -> Pubkey {
    let config = ProtocolConfig {
        discriminator: zolana_interface::state::discriminator::PROTOCOL_CONFIG,
        protocol_authority: Default::default(),
        tree_creation_authority: Default::default(),
        forester_authority: Default::default(),
        zone_creation_authority: Default::default(),
        tree_creation_is_permissionless: 0,
        zone_creation_is_permissionless: 1,
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

/// Install this program's own (squads-local) zone config with `authority` as
/// the recorded authority.
fn create_squads_zone_config(test: &mut SquadsZoneTest, authority: &Pubkey) -> Pubkey {
    let creator = Keypair::new();
    test.airdrop(&creator.pubkey(), 1_000_000_000)
        .expect("fund creator");
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
    let Some(mut test) = boot_with_spp() else {
        return;
    };
    let protocol_config = install_spp_protocol_config(&mut test);

    let authority = Keypair::new();
    test.airdrop(&authority.pubkey(), 1_000_000_000)
        .expect("fund authority");
    let squads_zone_config = create_squads_zone_config(&mut test, &authority.pubkey());
    let zone_auth = zone_auth_pda(&test.program_id);

    let ix = InitSppZoneConfig {
        authority: authority.pubkey(),
        zone_config: squads_zone_config,
        protocol_config,
        zone_auth,
        system_program: Pubkey::default(),
        spp_program: spp_program_id(),
    }
    .instruction();
    test.send(&[ix], &[&authority])
        .expect("init_spp_zone_config must succeed against a real SPP");

    // SPP's zone_config account is the zone's own zone_auth PDA, now created
    // and owned by SPP with the full expected contents.
    let account = test.svm.get_account(&zone_auth).expect("account exists");
    assert_eq!(account.owner, spp_program_id());
    let config: ZoneConfig = *bytemuck::from_bytes(&account.data);
    let (_, zone_auth_bump) = Pubkey::find_program_address(&[ZONE_AUTH_PDA_SEED], &test.program_id);
    let expected = ZoneConfig {
        discriminator: SPP_ZONE_CONFIG_DISCRIMINATOR,
        authority: Address::new_from_array(authority.pubkey().to_bytes()),
        program_id: Address::new_from_array(SQUADS_ZONE_PROGRAM_ID),
        zone_authority_transact_is_enabled: 1,
        bump: zone_auth_bump,
    };
    assert_eq!(config, expected);
}

#[test]
fn init_spp_zone_config_rejects_wrong_authority() {
    let Some(mut test) = boot_with_spp() else {
        return;
    };
    let protocol_config = install_spp_protocol_config(&mut test);

    let authority = Keypair::new();
    let impostor = Keypair::new();
    test.airdrop(&authority.pubkey(), 1_000_000_000)
        .expect("fund authority");
    test.airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund impostor");
    let squads_zone_config = create_squads_zone_config(&mut test, &authority.pubkey());
    let zone_auth = zone_auth_pda(&test.program_id);

    let ix = InitSppZoneConfig {
        authority: impostor.pubkey(),
        zone_config: squads_zone_config,
        protocol_config,
        zone_auth,
        system_program: Pubkey::default(),
        spp_program: spp_program_id(),
    }
    .instruction();
    let err = test
        .send(&[ix], &[&impostor])
        .expect_err("expected AuthorityMismatch");
    assert_eq!(custom_code(&err), SquadsZoneError::AuthorityMismatch as u32);
}
