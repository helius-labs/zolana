use anyhow::Result;
use solana_instruction::Instruction;
use solana_keypair::{read_keypair_file, Keypair};
use solana_message::{v1, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use zolana_client::{
    transaction_size::v1_transaction_size, ClientError, Proof, ProofCompressed, Rpc, SolanaRpc,
};
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

/// The largest budget the runtime grants a single transaction.
pub const MAX_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;
/// What the runtime grants per instruction when nothing asks for a budget.
pub const DEFAULT_COMPUTE_UNITS_PER_INSTRUCTION: u32 = 200_000;
/// The v1 header has no implicit default: leaving this unset would load zero
/// bytes of account data.
pub const LOADED_ACCOUNTS_DATA_SIZE_LIMIT: u32 = 64 * 1024 * 1024;

const COMPUTE_BUDGET_REQUEST_HEAP_FRAME: u8 = 1;
const COMPUTE_BUDGET_SET_UNIT_LIMIT: u8 = 2;

/// A v1 message carries its compute ceilings in the header, so a compute-budget
/// instruction in the list would only spend bytes the wide shapes cannot spare.
/// Lift what one carries into the config and drop it from the list. An unset
/// config field means zero rather than a default, so both ceilings are always
/// written; without an explicit limit the runtime's per-instruction default is
/// reproduced so a send keeps the budget it had.
#[track_caller]
pub fn split_compute_budget(ixs: &[Instruction]) -> (Vec<Instruction>, v1::TransactionConfig) {
    let mut compute_unit_limit = None;
    let mut heap_size = None;
    let mut kept: Vec<Instruction> = Vec::with_capacity(ixs.len());
    for instruction in ixs {
        if instruction.program_id != solana_compute_budget_interface::ID {
            kept.push(instruction.clone());
            continue;
        }
        let (discriminant, value) = instruction
            .data
            .split_first()
            .expect("a compute-budget instruction carries a discriminant");
        let value = value
            .get(..4)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(u32::from_le_bytes)
            .expect("a compute-budget instruction carries a u32");
        match *discriminant {
            COMPUTE_BUDGET_SET_UNIT_LIMIT => compute_unit_limit = Some(value),
            COMPUTE_BUDGET_REQUEST_HEAP_FRAME => heap_size = Some(value),
            other => panic!("compute-budget instruction {other} has no v1 header field"),
        }
    }
    let compute_unit_limit = compute_unit_limit.unwrap_or_else(|| {
        u32::try_from(kept.len())
            .ok()
            .and_then(|count| count.checked_mul(DEFAULT_COMPUTE_UNITS_PER_INSTRUCTION))
            .unwrap_or(MAX_COMPUTE_UNIT_LIMIT)
            .min(MAX_COMPUTE_UNIT_LIMIT)
    });
    let mut config = v1::TransactionConfig::empty()
        .with_compute_unit_limit(compute_unit_limit)
        .with_loaded_accounts_data_size_limit(LOADED_ACCOUNTS_DATA_SIZE_LIMIT);
    if let Some(heap_size) = heap_size {
        config = config.with_heap_size(heap_size);
    }
    (kept, config)
}

/// Send as a transaction **v1** message, the only format whose 4 KB limit fits a
/// large transact shape.
///
/// Deliberately no address lookup table: v1 has none, and a large shape's
/// instruction data alone exceeds the legacy 1232-byte limit, so a table would
/// not have rescued it either.
pub fn send_transaction_v1(
    rpc: &mut SolanaRpc,
    ixs: &[Instruction],
    payer: &Pubkey,
    signers: &[&Keypair],
) -> std::result::Result<Signature, ClientError> {
    let (instructions, config) = split_compute_budget(ixs);
    let (blockhash, _) = rpc.get_latest_blockhash()?;
    let message = v1::Message::try_compile_with_config(payer, &instructions, blockhash, config)
        .map_err(|error| ClientError::TransactionCompile(error.to_string()))?;
    let signers: Vec<&dyn Signer> = signers
        .iter()
        .map(|signer| *signer as &dyn Signer)
        .collect();
    let transaction = VersionedTransaction::try_new(VersionedMessage::V1(message), &signers)
        .map_err(|error| ClientError::SolanaTransactionSigning(error.to_string()))?;
    rpc.process_versioned_transaction(transaction)
}

/// Wire size of the v1 transaction [`send_transaction_v1`] would build, without
/// the compute-budget instructions it lifts into the header.
pub fn v1_transaction_len(
    ixs: &[Instruction],
    payer: &Pubkey,
    signatures: usize,
) -> std::result::Result<usize, ClientError> {
    let (instructions, _) = split_compute_budget(ixs);
    Ok(v1_transaction_size(payer, &instructions, signatures)?.bytes)
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
