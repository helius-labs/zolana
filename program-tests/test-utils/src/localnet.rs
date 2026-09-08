use anyhow::Result;
use solana_address_lookup_table_interface::instruction::{
    create_lookup_table, extend_lookup_table,
};
use solana_instruction::Instruction;
use solana_keypair::{read_keypair_file, Keypair};
use solana_message::{v0, AddressLookupTableAccount, Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::{versioned::VersionedTransaction, Transaction};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use zolana_client::{ClientError, Proof, ProofCompressed, Rpc, SolanaRpc};
use zolana_interface::instruction::instruction_data::merge_transact::MergeProof;
use zolana_smart_account_client::SMART_ACCOUNT_PROGRAM_ID;
use zolana_user_registry_interface::user_registry_program_id;

/// Arbitrary, the shared binary serves any genesis address.
pub const CUSTOM_RING_PROGRAM_ADDRESS: &str = "9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh";

pub const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
pub const DEFAULT_INDEXER_URL: &str = "http://127.0.0.1:8784";
pub const ZERO: [u8; 32] = [0u8; 32];
// Blinding positions in the fixed-position output layout
// `[spl_change, sol_change, recipients...]`.
pub const SPL_CHANGE_POSITION: u8 = 0;
pub const SOL_CHANGE_POSITION: u8 = 1;
pub const RECIPIENT_POSITION_BASE: u8 = 2;

/// Build the merge proof carried by a `merge` instruction, via the shared
/// `ProofCompressed::to_merge_proof` conversion.
pub fn pack_merge_proof(proof: &Proof) -> Result<MergeProof> {
    Ok(ProofCompressed::try_from(*proof)?.to_merge_proof()?)
}

pub fn send_transaction(
    rpc: &mut SolanaRpc,
    ixs: &[Instruction],
    payer: &Pubkey,
    signers: &[&Keypair],
) -> std::result::Result<Signature, ClientError> {
    let (blockhash, _) = rpc.get_latest_blockhash()?;
    let message = Message::new(ixs, Some(payer));
    let transaction = Transaction::new(signers, message, blockhash);
    rpc.send_transaction(&transaction)
}

const SLOT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);
const PACKET_DATA_SIZE: usize = 1232;

pub fn legacy_transaction_len(ixs: &[Instruction], payer: &Pubkey) -> usize {
    let message = Message::new(ixs, Some(payer));
    1 + 64 * usize::from(message.header.num_required_signatures) + message.serialize().len()
}

pub fn send_transaction_fitting(
    rpc: &mut SolanaRpc,
    ixs: &[Instruction],
    payer: &Keypair,
    signers: &[&Keypair],
) -> std::result::Result<Signature, ClientError> {
    if legacy_transaction_len(ixs, &payer.pubkey()) <= PACKET_DATA_SIZE {
        let mut all_signers: Vec<&Keypair> = vec![payer];
        all_signers.extend(signers.iter().copied());
        return send_transaction(rpc, ixs, &payer.pubkey(), &all_signers);
    }
    send_transaction_with_lookup_table(rpc, ixs, payer, signers)
}

pub fn lookup_table_addresses(ixs: &[Instruction]) -> Vec<Pubkey> {
    let mut addresses = Vec::new();
    for address in ixs.iter().flat_map(|ix| {
        ix.accounts
            .iter()
            .filter(|meta| !meta.is_signer)
            .map(|meta| meta.pubkey)
            .chain(std::iter::once(ix.program_id))
    }) {
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    addresses
}

pub fn send_transaction_with_lookup_table(
    rpc: &mut SolanaRpc,
    ixs: &[Instruction],
    payer: &Keypair,
    signers: &[&Keypair],
) -> std::result::Result<Signature, ClientError> {
    let addresses = lookup_table_addresses(ixs);
    let recent_slot = rpc.get_slot()?;
    wait_past_slot(rpc, recent_slot)?;
    let (create, table_address) = create_lookup_table(payer.pubkey(), payer.pubkey(), recent_slot);
    let extend = extend_lookup_table(
        table_address,
        payer.pubkey(),
        Some(payer.pubkey()),
        addresses.clone(),
    );
    send_transaction(rpc, &[create, extend], &payer.pubkey(), &[payer])?;
    let extended_slot = rpc.get_slot()?;
    wait_past_slot(rpc, extended_slot)?;
    let table = AddressLookupTableAccount {
        key: table_address,
        addresses,
    };
    let (blockhash, _) = rpc.get_latest_blockhash()?;
    let message = v0::Message::try_compile(
        &payer.pubkey(),
        ixs,
        std::slice::from_ref(&table),
        blockhash,
    )
    .map_err(|error| ClientError::Rpc(error.to_string()))?;
    let mut all_signers: Vec<&dyn Signer> = vec![payer];
    all_signers.extend(signers.iter().map(|signer| *signer as &dyn Signer));
    let transaction = VersionedTransaction::try_new(VersionedMessage::V0(message), &all_signers)
        .map_err(|error| ClientError::SolanaTransactionSigning(error.to_string()))?;
    rpc.process_versioned_transaction(transaction)
}

fn wait_past_slot(rpc: &SolanaRpc, slot: u64) -> std::result::Result<(), ClientError> {
    loop {
        if rpc.get_slot()? > slot {
            return Ok(());
        }
        std::thread::sleep(SLOT_POLL_INTERVAL);
    }
}

/// Normalized paths to build products and test data rooted at the workspace.
#[derive(Clone, Debug)]
pub struct WorkspaceArtifacts {
    root: PathBuf,
}

impl WorkspaceArtifacts {
    #[track_caller]
    pub fn new(root: impl AsRef<Path>) -> Self {
        let root = fs::canonicalize(root.as_ref()).unwrap_or_else(|error| {
            panic!(
                "workspace root {} is unavailable: {error}",
                root.as_ref().display()
            )
        });
        assert!(
            root.join("Cargo.toml").is_file(),
            "workspace root {} has no Cargo.toml",
            root.display()
        );
        Self { root }
    }

    pub fn root(&self) -> String {
        self.root.to_string_lossy().into_owned()
    }

    pub fn path(&self, relative: impl AsRef<Path>) -> String {
        self.root.join(relative).to_string_lossy().into_owned()
    }

    /// The prover creates this directory and lazily downloads keys into it. Its
    /// parent is validated here so a bad workspace root fails before startup.
    #[track_caller]
    pub fn prover_keys_dir(&self) -> String {
        let server = self.root.join("prover/server");
        assert!(
            server.is_dir(),
            "prover server directory is missing at {}",
            server.display()
        );
        server.join("proving-keys").to_string_lossy().into_owned()
    }
}

/// Use per-process paths so concurrent worktrees do not share validator state.
pub fn isolated_temp_path(label: &str) -> String {
    assert!(
        !label.is_empty()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
        "temporary path label must be non-empty ASCII alphanumeric, '-' or '_'"
    );
    std::env::temp_dir()
        .join(format!("{label}-{}", std::process::id()))
        .to_string_lossy()
        .into_owned()
}

/// Boot a fresh `solana-test-validator` with Photon (and no bundled prover) via
/// the `zolana` CLI, loading the given SBF programs and the Squads smart-account
/// program-config fixture. Mirrors the per-crate `restart_localnet` helpers the
/// swap, spp and ring test crates each used to copy.
///
/// The caller resolves the CLI path, ports, ledger/account directories and the
/// `(program_id, program_so)` list so this stays program-agnostic.
pub struct LocalnetValidator {
    pub cli_bin: String,
    pub working_dir: String,
    pub rpc_port: String,
    pub photon_port: String,
    pub ledger: String,
    pub account_dir: String,
    pub programs: Vec<(String, String)>,
}

pub struct UpgradeableProgram<'a> {
    pub address: &'a str,
    pub path: &'a str,
    pub authority: &'a str,
}

impl LocalnetValidator {
    #[track_caller]
    pub fn start(&self) {
        self.start_with_upgradeable_programs(&[]);
    }

    #[track_caller]
    pub fn start_with_upgradeable_programs(&self, upgradeable: &[UpgradeableProgram<'_>]) {
        assert_required_file("zolana CLI", &self.cli_bin);
        assert!(
            Path::new(&self.working_dir).is_dir(),
            "localnet working directory is missing at {}",
            self.working_dir
        );
        assert!(
            !self.programs.is_empty() || !upgradeable.is_empty(),
            "localnet has no SBF programs"
        );
        let mut program_ids = BTreeSet::<String>::new();
        for (program_id, program_so) in &self.programs {
            assert!(
                !program_id.trim().is_empty(),
                "localnet program id is empty"
            );
            assert!(
                program_ids.insert(program_id.clone()),
                "localnet program id {program_id} is duplicated"
            );
            assert_required_file(&format!("SBF program {program_id}"), program_so);
        }
        for program in upgradeable {
            assert!(
                !program.address.trim().is_empty(),
                "localnet program id is empty"
            );
            assert!(
                program_ids.insert(program.address.into()),
                "localnet program id {} is duplicated",
                program.address
            );
            assert_required_file(&format!("SBF program {}", program.address), program.path);
        }

        crate::smart_account::write_program_config_fixture(&self.account_dir);

        let mut args: Vec<String> = vec![
            "test-env".into(),
            "--local".into(),
            "--no-use-surfpool".into(),
            "--skip-prover".into(),
            "--rpc-port".into(),
            self.rpc_port.clone(),
            "--photon-port".into(),
            self.photon_port.clone(),
            "--ledger".into(),
            self.ledger.clone(),
        ];
        for (program_id, program_so) in &self.programs {
            args.push("--sbf-program".into());
            args.push(program_id.clone());
            args.push(program_so.clone());
        }
        for program in upgradeable {
            args.push("--upgradeable-program".into());
            args.push(program.address.into());
            args.push(program.path.into());
            args.push(program.authority.into());
        }
        args.push("--account-dir".into());
        args.push(self.account_dir.clone());

        let status = Command::new(&self.cli_bin)
            .current_dir(&self.working_dir)
            .args(&args)
            .status()
            .expect("run zolana test-validator");
        assert!(status.success(), "zolana test-validator start failed");
    }
}

/// Start the standard shielded-pool validator/Photon stack, optionally loading
/// additional workspace SBF programs. Program paths are workspace-relative.
pub fn start_shielded_pool_localnet(label: &str, extra_programs: &[(String, &str)]) {
    let artifacts = WorkspaceArtifacts::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| artifacts.path("target/debug/zolana"));
    let shielded_pool_id =
        std::env::var("SHIELDED_POOL_PROGRAM_ID").expect("SHIELDED_POOL_PROGRAM_ID must be set");
    let rpc_port = std::env::var("ZOLANA_LOCALNET_RPC_PORT").unwrap_or_else(|_| "8899".to_owned());
    let photon_port =
        std::env::var("ZOLANA_LOCALNET_PHOTON_PORT").unwrap_or_else(|_| "8784".to_owned());
    let shielded_pool_path = artifacts.path("target/deploy/shielded_pool_program.so");
    let upgrade_authority = match std::env::var("ZOLANA_SPP_UPGRADE_AUTHORITY_KEYPAIR") {
        Ok(path) => read_keypair_file(&path)
            .unwrap_or_else(|error| panic!("read SPP upgrade authority keypair {path}: {error}"))
            .pubkey()
            .to_string(),
        Err(_) => crate::smart_account::standard_accounts()
            .protocol_vault
            .to_string(),
    };
    let mut programs = vec![
        (
            user_registry_program_id().to_string(),
            artifacts.path("target/deploy/zolana_user_registry.so"),
        ),
        (
            SMART_ACCOUNT_PROGRAM_ID.to_string(),
            artifacts.path("target/deploy/squads_smart_account_program.so"),
        ),
    ];
    programs.extend(
        extra_programs
            .iter()
            .map(|(program_id, relative_path)| (program_id.clone(), artifacts.path(relative_path))),
    );

    let validator = LocalnetValidator {
        cli_bin: cli,
        working_dir: artifacts.root(),
        rpc_port,
        photon_port,
        ledger: isolated_temp_path(&format!("{label}-ledger")),
        account_dir: isolated_temp_path(&format!("{label}-smart-accounts")),
        programs,
    };
    validator.start_with_upgradeable_programs(&[UpgradeableProgram {
        address: &shielded_pool_id,
        path: &shielded_pool_path,
        authority: &upgrade_authority,
    }]);
}

#[track_caller]
fn assert_required_file(label: &str, path: &str) {
    assert!(
        Path::new(path).is_file(),
        "required {label} is missing at {path}; build it before running this test"
    );
}

#[cfg(test)]
mod tests {
    use super::isolated_temp_path;

    #[test]
    fn isolated_paths_are_stable_within_a_process_and_distinct_by_label() {
        assert_eq!(isolated_temp_path("alpha"), isolated_temp_path("alpha"));
        assert_ne!(isolated_temp_path("alpha"), isolated_temp_path("beta"));
    }
}
