use solana_instruction::Instruction;
use solana_keypair::{read_keypair_file, Keypair};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use std::{
    fs,
    path::{Path, PathBuf},
};
use zolana_client::{ClientError, ComputeBudgetConfig, Rpc, SolanaRpc};
use zolana_program_test::localnet::{LocalnetPorts, LocalnetValidator, UpgradeableProgram};
use zolana_smart_account_client::SMART_ACCOUNT_PROGRAM_ID;
use zolana_user_registry_interface::user_registry_program_id;

/// Arbitrary, the shared binary serves any genesis address.
pub const CUSTOM_RING_PROGRAM_ADDRESS: &str = "9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh";

pub const ZERO: [u8; 32] = [0u8; 32];
// Blinding positions in the fixed-position output layout
// `[spl_change, sol_change, recipients...]`.
pub const SPL_CHANGE_POSITION: u8 = 0;
pub const SOL_CHANGE_POSITION: u8 = 1;
pub const RECIPIENT_POSITION_BASE: u8 = 2;

/// Send as a transaction **v1** message, the only format whose 4 KB limit fits
/// a large transact shape.
///
/// The header states the ceiling a caller that does not name one used to
/// receive. v1 has no address lookup table.
pub fn send_transaction(
    rpc: &mut SolanaRpc,
    ixs: &[Instruction],
    payer: &Pubkey,
    signers: &[&Keypair],
) -> std::result::Result<Signature, ClientError> {
    send_transaction_with_budget(
        rpc,
        ixs,
        payer,
        signers,
        ComputeBudgetConfig::for_instruction_count(ixs.len()),
    )
}

/// [`send_transaction`] with the compute ceiling written into the v1 header.
pub fn send_transaction_with_budget(
    rpc: &mut SolanaRpc,
    ixs: &[Instruction],
    payer: &Pubkey,
    signers: &[&Keypair],
    budget: ComputeBudgetConfig,
) -> std::result::Result<Signature, ClientError> {
    let signers: Vec<&dyn Signer> = signers
        .iter()
        .map(|signer| *signer as &dyn Signer)
        .collect();
    rpc.create_and_send_transaction(ixs, *payer, &signers, budget)
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

/// Start the standard shielded-pool validator/Photon stack, optionally loading
/// additional workspace SBF programs. Program paths are workspace-relative.
pub fn start_shielded_pool_localnet(label: &str, extra_programs: &[(String, &str)]) {
    let artifacts = WorkspaceArtifacts::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| artifacts.path("target/debug/zolana"));
    let shielded_pool_id =
        std::env::var("SHIELDED_POOL_PROGRAM_ID").expect("SHIELDED_POOL_PROGRAM_ID must be set");
    let upgrade_authority = match std::env::var("ZOLANA_SPP_UPGRADE_AUTHORITY_KEYPAIR") {
        Ok(path) => read_keypair_file(&path)
            .unwrap_or_else(|error| panic!("read SPP upgrade authority keypair {path}: {error}"))
            .pubkey(),
        Err(_) => crate::smart_account::standard_accounts().protocol_vault,
    };
    let mut programs = vec![
        (
            user_registry_program_id(),
            artifacts
                .path("target/deploy/zolana_user_registry.so")
                .into(),
        ),
        (
            SMART_ACCOUNT_PROGRAM_ID,
            artifacts
                .path("target/deploy/squads_smart_account_program.so")
                .into(),
        ),
    ];
    programs.extend(extra_programs.iter().map(|(program_id, relative_path)| {
        (
            parse_pubkey(program_id),
            artifacts.path(relative_path).into(),
        )
    }));

    let account_dir = isolated_temp_path(&format!("{label}-smart-accounts"));
    crate::smart_account::write_program_config_fixture(&account_dir);
    LocalnetValidator {
        cli_bin: cli.into(),
        working_dir: artifacts.root().into(),
        ports: LocalnetPorts::checkout().expect("read this checkout's localnet ports"),
        account_dir: account_dir.into(),
        log_dir: artifacts.path("test-ledger").into(),
        programs,
        slot_time: None,
    }
    .start_with_upgradeable_programs(&[UpgradeableProgram {
        address: parse_pubkey(&shielded_pool_id),
        path: artifacts
            .path("target/deploy/shielded_pool_program.so")
            .into(),
        authority: upgrade_authority,
    }])
    .expect("start the shielded-pool localnet");
}

/// `ZOLANA_LOCALNET_URL`, else this checkout's validator.
#[track_caller]
pub fn localnet_rpc_url() -> String {
    std::env::var("ZOLANA_LOCALNET_URL").unwrap_or_else(|_| {
        LocalnetPorts::checkout()
            .expect("read this checkout's localnet ports")
            .rpc_url()
    })
}

/// `ZOLANA_INDEXER_URL`, else this checkout's Photon.
#[track_caller]
pub fn localnet_indexer_url() -> String {
    std::env::var("ZOLANA_INDEXER_URL").unwrap_or_else(|_| {
        LocalnetPorts::checkout_photon_url().expect("resolve this checkout's Photon URL")
    })
}

#[track_caller]
fn parse_pubkey(value: &str) -> Pubkey {
    value
        .parse()
        .unwrap_or_else(|error| panic!("{value} is not a pubkey: {error}"))
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
