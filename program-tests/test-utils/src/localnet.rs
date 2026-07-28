use anyhow::Result;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;
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
/// swap, spp and zone test crates each used to copy.
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

impl LocalnetValidator {
    #[track_caller]
    pub fn start(&self) {
        assert_required_file("zolana CLI", &self.cli_bin);
        assert!(
            Path::new(&self.working_dir).is_dir(),
            "localnet working directory is missing at {}",
            self.working_dir
        );
        assert!(!self.programs.is_empty(), "localnet has no SBF programs");
        let mut program_ids = BTreeSet::new();
        for (program_id, program_so) in &self.programs {
            assert!(
                !program_id.trim().is_empty(),
                "localnet program id is empty"
            );
            assert!(
                program_ids.insert(program_id),
                "localnet program id {program_id} is duplicated"
            );
            assert_required_file(&format!("SBF program {program_id}"), program_so);
        }

        crate::smart_account::write_program_config_fixture(&self.account_dir);

        let mut args: Vec<String> = vec![
            "test-env".into(),
            "--local".into(),
            "--no-use-surfpool".into(),
            "--with-photon".into(),
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
    let mut programs = vec![
        (
            shielded_pool_id,
            artifacts.path("target/deploy/shielded_pool_program.so"),
        ),
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

    LocalnetValidator {
        cli_bin: cli,
        working_dir: artifacts.root(),
        rpc_port,
        photon_port,
        ledger: isolated_temp_path(&format!("{label}-ledger")),
        account_dir: isolated_temp_path(&format!("{label}-smart-accounts")),
        programs,
    }
    .start();
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
