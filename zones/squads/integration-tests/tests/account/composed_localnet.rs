//! Composed localnet integration test: boots a REAL `zolana test-validator`
//! with both the SPP and the squads zone program loaded, initializes SPP's
//! protocol config for real, creates the squads zone's own `zone_config`, and
//! runs `init_spp_zone_config` (a real CPI into a real SPP) end to end.
//!
//! This is the composed-localnet counterpart to
//! `init_spp_zone_config_e2e.rs`'s LiteSVM version: it proves the multi-
//! program composition and bootstrap sequence work against a real validator,
//! not just LiteSVM.
//!
//! Full settlement scenarios (`transact`, `execute_proposal`,
//! `merge_transact`) additionally need the squads SDK to build the SPP-side
//! zone-rail proof alongside the zone proof (the pieces already exist in
//! `zolana-client`: `ZoneTransferP256Prover`, `MergeZoneProver`). Adding
//! those scenarios here is follow-up work. A stale `target/prover-server`
//! binary rejects zone-proof requests with "no 'addressTreeHeight'..."; fix
//! with `just build-prover-server` and restart the prover.
//!
//! GATING: requires the `zolana` CLI binary and every `.so` this test loads
//! (SPP, user-registry, smart-account from the main repo; the squads zone
//! from its nested workspace). Build them with `just build-programs` and
//! `cd zones/squads/program && cargo build-sbf --features bpf-entrypoint`.
//! Skips (does not fail) if any binary is missing.
//!
//! Run with:
//!   cargo test --manifest-path zones/squads/Cargo.toml -p squads-zone-tests --test composed_localnet -- --nocapture

use std::path::Path;

use anyhow::Result;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use squads_zone_tests::{default_program_path, default_spp_program_path};
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::{
    instruction::CreateProtocolConfig,
    pda,
    state::{
        discriminator::ZONE_CONFIG as SPP_ZONE_CONFIG_DISCRIMINATOR, ZoneConfig as SppZoneConfig,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_squads_interface::{
    instruction::{
        builders::{CreateZoneConfig, InitSppZoneConfig},
        CreateZoneConfigIxData,
    },
    SQUADS_ZONE_PROGRAM_ID, ZONE_AUTH_PDA_SEED, ZONE_CONFIG_PDA_SEED,
};
use zolana_test_utils::smart_account::{self, execute_sync_ix, StandardSigners};
use zolana_user_registry_interface::user_registry_program_id;

const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";

fn squads_zone_program_id() -> Pubkey {
    Pubkey::new_from_array(SQUADS_ZONE_PROGRAM_ID)
}

fn spp_program_id() -> Pubkey {
    Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID)
}

fn zone_config_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[ZONE_CONFIG_PDA_SEED], program_id).0
}

fn zone_auth_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[ZONE_AUTH_PDA_SEED], program_id).0
}

fn send_transaction(
    rpc: &mut SolanaRpc,
    ixs: &[Instruction],
    payer: &Pubkey,
    signers: &[&Keypair],
) -> Result<()> {
    let (blockhash, _) = rpc.get_latest_blockhash()?;
    let message = Message::new(ixs, Some(payer));
    let transaction = Transaction::new(signers, message, blockhash);
    rpc.send_transaction(&transaction)?;
    Ok(())
}

/// Every `.so` this test loads exists, or `None` (caller skips cleanly).
fn all_binaries_present() -> Option<(
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
)> {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../..");
    let user_registry_so =
        std::path::PathBuf::from(format!("{root}/target/deploy/zolana_user_registry.so"));
    let smart_account_so = std::path::PathBuf::from(format!(
        "{root}/target/deploy/squads_smart_account_program.so"
    ));
    let spp_so = default_spp_program_path();
    let squads_so = default_program_path();
    for path in [&user_registry_so, &smart_account_so, &spp_so, &squads_so] {
        if !path.exists() {
            eprintln!("skipping composed_localnet: missing {}", path.display());
            return None;
        }
    }
    Some((user_registry_so, smart_account_so, spp_so, squads_so))
}

/// Restart a fresh validator loaded with SPP, the user-registry, the
/// smart-account program (needed for `execute_sync_ix`), and the squads zone.
fn restart_localnet(
    user_registry_so: &Path,
    smart_account_so: &Path,
    spp_so: &Path,
    squads_so: &Path,
) {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../..");
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| format!("{root}/target/debug/zolana"));

    let account_dir = "/tmp/zolana-squads-composed-accounts";
    smart_account::write_program_config_fixture(account_dir);

    let status = std::process::Command::new(&cli)
        .current_dir(root)
        .args([
            "test-validator",
            "--no-use-surfpool",
            "--skip-prover",
            "--ledger",
            "/tmp/zolana-squads-composed-ledger",
            "--sbf-program",
            &spp_program_id().to_string(),
            &spp_so.to_string_lossy(),
            "--sbf-program",
            &user_registry_program_id().to_string(),
            &user_registry_so.to_string_lossy(),
            "--sbf-program",
            &smart_account::SMART_ACCOUNT_PROGRAM_ID.to_string(),
            &smart_account_so.to_string_lossy(),
            "--sbf-program",
            &squads_zone_program_id().to_string(),
            &squads_so.to_string_lossy(),
            "--account-dir",
            account_dir,
        ])
        .status()
        .expect("run zolana test-validator");
    assert!(status.success(), "zolana test-validator restart failed");
}

#[test]
fn init_spp_zone_config_against_real_validator() {
    let Some((user_registry_so, smart_account_so, spp_so, squads_so)) = all_binaries_present()
    else {
        return;
    };
    restart_localnet(&user_registry_so, &smart_account_so, &spp_so, &squads_so);

    let rpc_url = std::env::var("ZOLANA_LOCALNET_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.into());
    let mut rpc = SolanaRpc::new(rpc_url);
    rpc.assert_executable(&spp_program_id())
        .expect("SPP must be loaded");
    rpc.assert_executable(&squads_zone_program_id())
        .expect("squads zone must be loaded");

    let payer = Keypair::new();
    let authority = Keypair::new();
    rpc.airdrop(&payer.pubkey(), 100_000_000_000)
        .expect("fund payer");
    rpc.airdrop(&authority.pubkey(), 1_000_000_000)
        .expect("fund authority");

    // Standard smart-account PDAs, matching the pattern every localnet test in
    // this repo uses to initialize SPP's protocol config.
    let accounts = smart_account::standard_accounts();
    let forester_keypair = Keypair::new();
    let merge_keypair = Keypair::new();
    let tree_keypair = Keypair::new();
    let zone_keypair = Keypair::new();
    for keypair in [
        &forester_keypair,
        &merge_keypair,
        &tree_keypair,
        &zone_keypair,
    ] {
        rpc.airdrop(&keypair.pubkey(), 1_000_000_000).expect("fund");
    }
    for ix in accounts.create_ixs(
        &payer.pubkey(),
        StandardSigners {
            protocol: authority.pubkey(),
            forester: forester_keypair.pubkey(),
            merge: merge_keypair.pubkey(),
            tree: tree_keypair.pubkey(),
            zone: zone_keypair.pubkey(),
        },
    ) {
        send_transaction(&mut rpc, &[ix], &payer.pubkey(), &[&payer])
            .expect("create smart accounts");
    }
    rpc.airdrop(&accounts.protocol_vault, 5_000_000_000)
        .expect("fund protocol vault");

    // Permissionless zone creation lets `init_spp_zone_config`'s payer create
    // SPP's zone_config without the protocol vault co-signing.
    let create_config_ix = CreateProtocolConfig {
        authority: accounts.protocol_vault,
        protocol_authority: accounts.protocol_vault.to_bytes().into(),
        tree_creation_authority: accounts.tree_vault.to_bytes().into(),
        tree_creation_is_permissionless: false,
        forester_authority: accounts.forester_vault.to_bytes().into(),
        zone_creation_authority: accounts.zone_vault.to_bytes().into(),
        zone_creation_is_permissionless: true,
        spl_interface_creation_is_permissionless: false,
    }
    .instruction();
    let create_config_sync = execute_sync_ix(
        &accounts.protocol_settings,
        0,
        &[authority.pubkey()],
        &[create_config_ix],
    );
    send_transaction(
        &mut rpc,
        &[create_config_sync],
        &payer.pubkey(),
        &[&payer, &authority],
    )
    .expect("create protocol config");

    // The squads zone's own zone_config (distinct from SPP's).
    let squads_authority = Keypair::new();
    rpc.airdrop(&squads_authority.pubkey(), 1_000_000_000)
        .expect("fund squads authority");
    let squads_zone_config = zone_config_pda(&squads_zone_program_id());
    let create_squads_zone_config_ix = CreateZoneConfig {
        creator: payer.pubkey(),
        zone_config: squads_zone_config,
        system_program: Pubkey::default(),
        data: CreateZoneConfigIxData {
            authority: squads_authority.pubkey(),
            co_signer: Pubkey::default(),
            max_proposal_lifetime: 3_600,
            auditor_keys: vec![[9u8; 33]],
            merge_authorities: vec![],
        },
    }
    .instruction();
    send_transaction(
        &mut rpc,
        &[create_squads_zone_config_ix],
        &payer.pubkey(),
        &[&payer],
    )
    .expect("create squads zone_config");

    // Register the squads zone with SPP: a real CPI into a real SPP.
    let zone_auth = zone_auth_pda(&squads_zone_program_id());
    let init_ix = InitSppZoneConfig {
        authority: squads_authority.pubkey(),
        zone_config: squads_zone_config,
        protocol_config: pda::protocol_config(),
        zone_auth,
        system_program: Pubkey::default(),
        spp_program: spp_program_id(),
    }
    .instruction();
    send_transaction(
        &mut rpc,
        &[init_ix],
        &payer.pubkey(),
        &[&payer, &squads_authority],
    )
    .expect("init_spp_zone_config against a real SPP");

    // SPP's zone_config account is the zone's own zone_auth PDA, now created
    // and owned by SPP with the full expected contents.
    let account = rpc
        .get_account(Address::new_from_array(zone_auth.to_bytes()))
        .expect("rpc get_account")
        .expect("SPP zone_config exists at the zone_auth address");
    assert_eq!(account.owner, SHIELDED_POOL_PROGRAM_ID.into());
    let config: SppZoneConfig = *bytemuck::from_bytes(&account.data);
    let (_, zone_auth_bump) =
        Pubkey::find_program_address(&[ZONE_AUTH_PDA_SEED], &squads_zone_program_id());
    let expected = SppZoneConfig {
        discriminator: SPP_ZONE_CONFIG_DISCRIMINATOR,
        authority: Address::new_from_array(squads_authority.pubkey().to_bytes()),
        program_id: Address::new_from_array(SQUADS_ZONE_PROGRAM_ID),
        zone_authority_transact_is_enabled: 1,
        bump: zone_auth_bump,
    };
    assert_eq!(config, expected);
}
