//! End-to-end on-chain test for `init_spp_ring_config` (tag 16): the ring's
//! first real CPI into a REAL SPP program loaded into the same LiteSVM
//! instance. Confirms the ring-auth-signed CPI creates SPP's `ring_config`
//! account (identical address to this program's own `ring_auth` PDA) with
//! the expected owner, discriminator, and fields.
//!
//! GATING: requires both prebuilt binaries (skips if either is missing).
//! Build them first:
//!   cd rings/squads/program && cargo build-sbf --features bpf-entrypoint
//!   just build-programs   (from the repo root, builds the SPP .so)
//! Run with:
//!   cargo test --manifest-path rings/squads/Cargo.toml -p squads-ring-tests --test init_spp_ring_config_e2e -- --nocapture

use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_ring_tests::{custom_code, default_spp_program_path, SquadsRingTest};
use zolana_interface::{
    state::{
        discriminator::RING_CONFIG as SPP_RING_CONFIG_DISCRIMINATOR, ProtocolConfig, RingConfig,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_squads_interface::{
    error::SquadsRingError,
    instruction::{
        builders::{CreateRingConfig, InitSppRingConfig},
        CreateRingConfigIxData,
    },
    RING_AUTH_PDA_SEED, RING_CONFIG_PDA_SEED, SQUADS_RING_PROGRAM_ID,
};

fn ring_config_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[RING_CONFIG_PDA_SEED], program_id).0
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

/// Boot LiteSVM with both the squads ring program and a REAL SPP program;
/// returns `None` (clean skip) if either `.so` is missing.
fn boot_with_spp() -> Option<SquadsRingTest> {
    let mut test = SquadsRingTest::new().expect("boot")?;
    let loaded = test
        .add_program(&spp_program_id(), &default_spp_program_path())
        .expect("add SPP program");
    if !loaded {
        eprintln!("skipping init_spp_ring_config_e2e: SPP .so missing - run `just build-programs`");
        return None;
    }
    Some(test)
}

/// Install SPP's `ProtocolConfig` directly (bypassing its own create
/// instruction) with `ring_activation_is_permissionless` set, so the created
/// ring config starts activated.
fn install_spp_protocol_config(test: &mut SquadsRingTest) -> Pubkey {
    let config = ProtocolConfig {
        discriminator: zolana_interface::state::discriminator::PROTOCOL_CONFIG,
        protocol_authority: Default::default(),
        tree_creation_authority: Default::default(),
        forester_authority: Default::default(),
        ring_creation_authority: Default::default(),
        fee_authority: Default::default(),
        tree_creation_is_permissionless: 0,
        ring_activation_is_permissionless: 1,
        spl_interface_creation_is_permissionless: 0,
        next_tree_id: 0,
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

/// Install this program's own (squads-local) ring config with `authority` as
/// the recorded authority.
fn create_squads_ring_config(test: &mut SquadsRingTest, authority: &Pubkey) -> Pubkey {
    let creator = Keypair::new();
    test.airdrop(&creator.pubkey(), 1_000_000_000)
        .expect("fund creator");
    let ring_config = ring_config_pda(&test.program_id);
    let ix = CreateRingConfig {
        creator: creator.pubkey(),
        ring_config,
        system_program: Pubkey::default(),
        data: CreateRingConfigIxData {
            authority: *authority,
            co_signer: Pubkey::default(),
            max_proposal_lifetime: 3_600,
            auditor_keys: vec![[9u8; 33]],
            merge_authorities: vec![],
        },
    }
    .instruction();
    test.send(&[ix], &[&creator]).expect("create_ring_config");
    ring_config
}

#[test]
fn init_spp_ring_config_happy_path() {
    let Some(mut test) = boot_with_spp() else {
        return;
    };
    let protocol_config = install_spp_protocol_config(&mut test);

    let authority = Keypair::new();
    test.airdrop(&authority.pubkey(), 1_000_000_000)
        .expect("fund authority");
    let squads_ring_config = create_squads_ring_config(&mut test, &authority.pubkey());
    let ring_auth = ring_auth_pda(&test.program_id);

    let ix = InitSppRingConfig {
        authority: authority.pubkey(),
        ring_config: squads_ring_config,
        protocol_config,
        ring_auth,
        system_program: Pubkey::default(),
        spp_program: spp_program_id(),
    }
    .instruction();
    test.send(&[ix], &[&authority])
        .expect("init_spp_ring_config must succeed against a real SPP");

    // SPP's ring_config account is the ring's own ring_auth PDA, now created
    // and owned by SPP with the full expected contents.
    let account = test.svm.get_account(&ring_auth).expect("account exists");
    assert_eq!(account.owner, spp_program_id());
    let config: RingConfig = *bytemuck::from_bytes(&account.data);
    let (_, ring_auth_bump) = Pubkey::find_program_address(&[RING_AUTH_PDA_SEED], &test.program_id);
    let expected = RingConfig {
        discriminator: SPP_RING_CONFIG_DISCRIMINATOR,
        authority: Address::new_from_array(authority.pubkey().to_bytes()),
        program_id: Address::new_from_array(SQUADS_RING_PROGRAM_ID),
        ring_authority_transact_is_enabled: 0,
        paused: 0,
        activated: 1,
        bump: ring_auth_bump,
    };
    assert_eq!(config, expected);
}

#[test]
fn init_spp_ring_config_rejects_wrong_authority() {
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
    let squads_ring_config = create_squads_ring_config(&mut test, &authority.pubkey());
    let ring_auth = ring_auth_pda(&test.program_id);

    let ix = InitSppRingConfig {
        authority: impostor.pubkey(),
        ring_config: squads_ring_config,
        protocol_config,
        ring_auth,
        system_program: Pubkey::default(),
        spp_program: spp_program_id(),
    }
    .instruction();
    let err = test
        .send(&[ix], &[&impostor])
        .expect_err("expected AuthorityMismatch");
    assert_eq!(custom_code(&err), SquadsRingError::AuthorityMismatch as u32);
}
