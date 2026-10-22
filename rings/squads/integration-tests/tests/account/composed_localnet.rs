//! Composed localnet integration test: boots a REAL validator through
//! `zolana test-env` with SPP (upgradeable, as `create_protocol_config`
//! requires), the user registry, the smart-account program, and the squads
//! ring loaded. It initializes SPP's protocol config and a tree for real,
//! creates the squads ring's own `ring_config`, runs `init_spp_ring_config` (a
//! real CPI into a real SPP), then settles a squads `deposit` through SPP
//! `ring_deposit` and checks the emitted event and the escrowed lamports.
//!
//! This is the composed-localnet counterpart to the LiteSVM suites: they stop
//! at the SPP forwarding boundary, while this one proves the forwarded account
//! lists and payloads are accepted by the real SPP program (including its event
//! self-CPI, which needs the forwarded SPP program account).
//!
//! Proof-bearing settlements (`transact`, `execute_proposal`,
//! `merge_transact`) additionally need the SPP-side ring-rail proof built
//! alongside the ring proof; they are covered by the keypair and smart-account
//! lifecycle suites.
//!
//! GATING: requires the `zolana` CLI binary, the pinned surfpool
//! (`just ensure-surfpool`), and every `.so` this test loads (SPP,
//! user-registry, smart-account from the main repo; the squads ring from its
//! nested workspace). Build them with `just build-programs`, `just build-cli`
//! and `cd rings/squads/program && cargo build-sbf --features bpf-entrypoint`.
//! Skips (does not fail) if any binary is missing.
//!
//! Ports follow the checkout's `ZOLANA_PORT_OFFSET` (RPC `8899 + offset`), or
//! `ZOLANA_LOCALNET_RPC_PORT` / `ZOLANA_LOCALNET_PHOTON_PORT` when set.
//!
//! Run with:
//!   cargo test --manifest-path rings/squads/Cargo.toml -p squads-ring-tests --test composed_localnet -- --nocapture

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use base64::{engine::general_purpose::STANDARD, Engine};
use solana_address::Address;
use solana_keypair::{read_keypair_file, Keypair};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_ring_tests::{default_program_path, default_spp_program_path};
use zolana_client::{Rpc, SolanaRpc};
use zolana_event::{EncryptedRingDepositData as EventRingDepositData, EncryptedRingDepositOutput};
use zolana_event_parser::indexed_events_from_instruction_groups;
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::{
    instruction::{DepositAssetKind, EncryptedRingDepositData},
    pda,
    state::{
        discriminator::RING_CONFIG as SPP_RING_CONFIG_DISCRIMINATOR, RingConfig as SppRingConfig,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program::instruction::{DepositAsset, RingAssetDeposit, RingDeposit};
use zolana_program_test::{
    localnet::LocalnetPorts, ring_deposit_output_from_event, RingDepositOutput,
};
use zolana_squads_interface::{
    constants::{ENCRYPTION_SCHEME_X25519_AES, OWNER_KIND_KEYPAIR, VIEWING_KEY_STATE_ACTIVE},
    instruction::{
        builders::{CreateRingConfig, Deposit, InitSppRingConfig},
        CreateRingConfigIxData, DepositIxData,
    },
    state::viewing_key_account::ViewingKeyAccount,
    RING_AUTH_PDA_SEED, RING_CONFIG_PDA_SEED, SQUADS_RING_PROGRAM_ID,
};
use zolana_test_utils::{
    harness::{BootstrapConfig, LocalnetHarness},
    localnet::{isolated_temp_path, send_transaction},
    smart_account::{self, SMART_ACCOUNT_PROGRAM_ID},
};
use zolana_user_registry_interface::user_registry_program_id;

const DEPOSIT_AMOUNT: u64 = 1_000_000;

fn squads_ring_program_id() -> Pubkey {
    Pubkey::new_from_array(SQUADS_RING_PROGRAM_ID)
}

fn spp_program_id() -> Pubkey {
    Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID)
}

fn ring_config_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[RING_CONFIG_PDA_SEED], program_id).0
}

fn ring_auth_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[RING_AUTH_PDA_SEED], program_id)
}

fn repo_root() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../.."))
}

/// A 32-byte value inside the BN254 field range (top byte cleared).
fn field(seed: u8) -> [u8; 32] {
    let mut f = [seed; 32];
    f[0] = 0;
    f
}

/// The programs this test loads, or `None` (caller skips cleanly) when the CLI
/// or any `.so` is missing.
struct Binaries {
    cli: PathBuf,
    user_registry: PathBuf,
    smart_account: PathBuf,
    spp: PathBuf,
    squads: PathBuf,
}

fn binaries() -> Option<Binaries> {
    let root = repo_root();
    let binaries = Binaries {
        cli: std::env::var("ZOLANA_CLI_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|_| root.join("target/debug/zolana")),
        user_registry: root.join("target/deploy/zolana_user_registry.so"),
        smart_account: root.join("target/deploy/squads_smart_account_program.so"),
        spp: default_spp_program_path(),
        squads: default_program_path(),
    };
    for path in [
        &binaries.cli,
        &binaries.user_registry,
        &binaries.smart_account,
        &binaries.spp,
        &binaries.squads,
    ] {
        if !path.exists() {
            eprintln!("skipping composed_localnet: missing {}", path.display());
            return None;
        }
    }
    Some(binaries)
}

fn localnet_ports() -> LocalnetPorts {
    LocalnetPorts::checkout().expect("checkout localnet ports")
}

/// The SPP upgrade authority `create_protocol_config` is signed by: the
/// exported keypair when a recipe sets one, else the protocol vault (which
/// `setup_protocol_accounts` signs for through the smart-account program).
fn spp_upgrade_authority() -> Pubkey {
    match std::env::var("ZOLANA_SPP_UPGRADE_AUTHORITY_KEYPAIR") {
        Ok(path) => read_keypair_file(&path)
            .unwrap_or_else(|error| panic!("read SPP upgrade authority keypair {path}: {error}"))
            .pubkey(),
        Err(_) => smart_account::standard_accounts().protocol_vault,
    }
}

/// Write a squads viewing key account fixture (the deposit recipient) into the
/// validator's account directory. Creating one on-chain needs a key-encryption
/// proof; the deposit only reads `owner` and `nullifier_pubkey`.
fn write_recipient_vka_fixture(account_dir: &Path, address: &Pubkey, vka: &ViewingKeyAccount) {
    let data = STANDARD.encode(vka.serialize().expect("serialize vka"));
    let json = format!(
        r#"{{"pubkey":"{address}","account":{{"lamports":100000000,"data":["{data}","base64"],"owner":"{}","executable":false,"rentEpoch":18446744073709551615}}}}"#,
        squads_ring_program_id()
    );
    fs::create_dir_all(account_dir).expect("create account dir");
    fs::write(account_dir.join("squads_recipient_vka.json"), json).expect("write vka fixture");
}

/// A `zolana test-env` localnet on this checkout's ports, stopped on drop.
struct Localnet {
    cli: PathBuf,
    ports: LocalnetPorts,
}

impl Localnet {
    fn test_env(&self) -> Command {
        let mut command = Command::new(&self.cli);
        command
            .current_dir(repo_root())
            .arg("test-env")
            .args(["--skip-prover", "--skip-indexer"])
            .arg("--rpc-port")
            .arg(self.ports.rpc.to_string())
            .arg("--photon-port")
            .arg(self.ports.photon.to_string());
        command
    }

    fn start(binaries: &Binaries, account_dir: &Path, log_dir: &Path) -> Self {
        let localnet = Self {
            cli: binaries.cli.clone(),
            ports: localnet_ports(),
        };
        let mut command = localnet.test_env();
        command
            .arg("--local")
            .arg("--account-dir")
            .arg(account_dir)
            .arg("--log-dir")
            .arg(log_dir);
        for (address, path) in [
            (user_registry_program_id(), &binaries.user_registry),
            (SMART_ACCOUNT_PROGRAM_ID, &binaries.smart_account),
            (squads_ring_program_id(), &binaries.squads),
        ] {
            command
                .arg("--sbf-program")
                .arg(address.to_string())
                .arg(path);
        }
        command
            .arg("--upgradeable-program")
            .arg(spp_program_id().to_string())
            .arg(&binaries.spp)
            .arg(spp_upgrade_authority().to_string());
        let status = command.status().expect("run zolana test-env");
        assert!(status.success(), "zolana test-env start failed: {status}");
        localnet
    }
}

impl Drop for Localnet {
    fn drop(&mut self) {
        let status = self.test_env().arg("--stop").status();
        if !matches!(status, Ok(status) if status.success()) {
            eprintln!("failed to stop the composed localnet: {status:?}");
        }
    }
}

#[test]
fn init_spp_ring_config_and_deposit_against_real_validator() {
    let Some(binaries) = binaries() else {
        return;
    };

    let account_dir = PathBuf::from(isolated_temp_path("squads-composed-accounts"));
    let log_dir = PathBuf::from(isolated_temp_path("squads-composed-logs"));
    smart_account::write_program_config_fixture(&account_dir);
    let recipient_vka_address = Keypair::new().pubkey();
    let recipient_vka = ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: Address::new_from_array(field(9)),
        state: VIEWING_KEY_STATE_ACTIVE,
        encryption_scheme: ENCRYPTION_SCHEME_X25519_AES,
        owner_kind: OWNER_KIND_KEYPAIR,
        shared_viewing_key: [2u8; 33],
        shared_viewing_key_commitment: field(4),
        key_nonce: 0,
        nullifier_pubkey: field(5),
        key_ciphertext_ephemeral: [0u8; 33],
        encrypted_nullifier_secret: [0u8; 31],
        recovery_keys: vec![],
        recovery_key_ciphertexts: vec![],
        auditor_keys: vec![],
        auditor_key_ciphertexts: vec![],
    };
    write_recipient_vka_fixture(&account_dir, &recipient_vka_address, &recipient_vka);

    let localnet = Localnet::start(&binaries, &account_dir, &log_dir);
    let mut rpc = SolanaRpc::new(localnet.ports.rpc_url());
    rpc.assert_executable(&spp_program_id())
        .expect("SPP must be loaded");
    rpc.assert_executable(&squads_ring_program_id())
        .expect("squads ring must be loaded");

    // Permissionless ring activation lets `init_spp_ring_config` create an
    // activated SPP ring config without the ring vault co-signing.
    let setup = LocalnetHarness::<()>::setup_protocol_accounts(
        &mut rpc,
        &BootstrapConfig {
            label: "squads-composed",
            extra_programs: vec![],
            ring_activation_is_permissionless: true,
            fund_merge_vault: false,
        },
    )
    .expect("create protocol config");
    let (tree, _tree_address, _tree_id) =
        LocalnetHarness::<()>::create_tree(&mut rpc, &setup, None).expect("create tree");
    let payer = &setup.payer;

    // The squads ring's own ring_config (distinct from SPP's).
    let squads_authority = Keypair::new();
    rpc.airdrop(&squads_authority.pubkey(), 1_000_000_000)
        .expect("fund squads authority");
    let squads_ring_config = ring_config_pda(&squads_ring_program_id());
    let create_squads_ring_config_ix = CreateRingConfig {
        creator: payer.pubkey(),
        ring_config: squads_ring_config,
        system_program: Pubkey::default(),
        data: CreateRingConfigIxData {
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
        &[create_squads_ring_config_ix],
        &payer.pubkey(),
        &[payer],
    )
    .expect("create squads ring_config");

    // Register the squads ring with SPP: a real CPI into a real SPP.
    let (ring_auth, ring_auth_bump) = ring_auth_pda(&squads_ring_program_id());
    let init_ix = InitSppRingConfig {
        authority: squads_authority.pubkey(),
        ring_config: squads_ring_config,
        protocol_config: pda::protocol_config(),
        ring_auth,
        system_program: Pubkey::default(),
        spp_program: spp_program_id(),
    }
    .instruction();
    send_transaction(
        &mut rpc,
        &[init_ix],
        &payer.pubkey(),
        &[payer, &squads_authority],
    )
    .expect("init_spp_ring_config against a real SPP");

    // SPP's ring_config account is the ring's own ring_auth PDA, now created
    // and owned by SPP with the full expected contents.
    let account = rpc
        .get_account(Address::new_from_array(ring_auth.to_bytes()))
        .expect("rpc get_account")
        .expect("SPP ring_config exists at the ring_auth address");
    assert_eq!(account.owner, SHIELDED_POOL_PROGRAM_ID.into());
    let config: SppRingConfig = *bytemuck::from_bytes(&account.data);
    let expected = SppRingConfig {
        discriminator: SPP_RING_CONFIG_DISCRIMINATOR,
        authority: Address::new_from_array(squads_authority.pubkey().to_bytes()),
        program_id: Address::new_from_array(SQUADS_RING_PROGRAM_ID),
        ring_authority_transact_is_enabled: 0,
        paused: 0,
        activated: 1,
        bump: ring_auth_bump,
    };
    assert_eq!(config, expected);

    // A public SOL deposit into a squads UTXO owned by the recipient viewing
    // key account, settled through SPP `ring_deposit`.
    let data = DepositIxData {
        view_tag: field(1),
        blinding: field(2),
        amount: DEPOSIT_AMOUNT,
        asset: DepositAssetKind::Sol,
    };
    let spp_accounts = RingDeposit {
        tree,
        depositor: payer.pubkey(),
        ring_program_id: squads_ring_program_id(),
        deposits: vec![RingAssetDeposit {
            asset: DepositAsset::Sol,
            view_tag: data.view_tag,
            owner_utxo_hash: [0u8; 32],
            amount: DEPOSIT_AMOUNT,
            ring_data_hash: [0u8; 32],
            encrypted: EncryptedRingDepositData {
                tx_viewing_pk: [0u8; 33],
                salt: [0u8; 16],
                ciphertext: vec![],
            },
        }],
    }
    .instruction()
    .expect("ring deposit layout")
    .accounts;
    let deposit_ix = Deposit {
        recipient_viewing_key_account: recipient_vka_address,
        spp_accounts,
        data,
    }
    .instruction();

    let sol_interface = Address::new_from_array(pda::sol_interface().to_bytes());
    let sol_interface_before = rpc
        .get_account(sol_interface)
        .expect("rpc get_account")
        .map_or(0, |account| account.lamports);
    let signature = send_transaction(&mut rpc, &[deposit_ix], &payer.pubkey(), &[payer])
        .expect("squads deposit settles through SPP");
    let sol_interface_after = rpc
        .get_account(sol_interface)
        .expect("rpc get_account")
        .expect("sol interface exists after a SOL deposit")
        .lamports;
    assert_eq!(sol_interface_after - sol_interface_before, DEPOSIT_AMOUNT);

    let groups = rpc
        .fetch_confirmed_instruction_groups(&signature)
        .expect("fetch deposit instruction groups");
    let events = indexed_events_from_instruction_groups(spp_program_id(), &groups.groups);
    let event = ring_deposit_output_from_event(events.first().expect("deposit emits an event"))
        .expect("ring deposit event");

    let owner_hash = Poseidon::hashv(&[
        recipient_vka.owner.as_ref(),
        recipient_vka.nullifier_pubkey.as_slice(),
    ])
    .expect("owner hash");
    let owner_utxo_hash = Poseidon::hashv(&[owner_hash.as_slice(), data.blinding.as_slice()])
        .expect("owner utxo hash");
    let expected_event = RingDepositOutput {
        view_tag: data.view_tag,
        utxo_hash: event.utxo_hash,
        output_tree: tree.to_bytes(),
        leaf_index: 0,
        output: EncryptedRingDepositOutput {
            owner_utxo_hash,
            asset: [0u8; 32],
            amount: DEPOSIT_AMOUNT,
            data_hash: None,
            ring_program_id: SQUADS_RING_PROGRAM_ID,
            ring_data_hash: [0u8; 32],
            encrypted: EventRingDepositData {
                tx_viewing_pk: [0u8; 33],
                salt: [0u8; 16],
                ciphertext: data.blinding.to_vec(),
            },
        },
    };
    assert_eq!(event, expected_event);
}
