use std::path::{Path, PathBuf};

use litesvm::LiteSVM;
use solana_account::Account;
use solana_clock::Clock;
use solana_instruction::Instruction;
use solana_instruction_error::InstructionError;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;
use zolana_squads_interface::SQUADS_RING_PROGRAM_ID;

use zolana_interface::BPF_LOADER_UPGRADEABLE_PUBKEY;

/// The prover server URL. Resolves `ZOLANA_PROVER_URL` with fallback to
/// `default`, the same resolution `spawn_prover` uses, so `.prove(...)` calls
/// target the server `spawn_prover` starts. Running `cargo test` directly does
/// not auto-load `.env` (see the repo `CLAUDE.md` per-clone port isolation).
pub fn prover_url(default: &str) -> String {
    std::env::var("ZOLANA_PROVER_URL").unwrap_or_else(|_| default.to_string())
}

pub fn custom_code(err: &TransactionError) -> u32 {
    match err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => *code,
        other => panic!("expected a custom instruction error, got {other:?}"),
    }
}

/// Default location of the prebuilt Squads ring SBF binary, overridable with the
/// `SQUADS_RING_PROGRAM_PATH` env var.
///
/// The nested `rings/squads` workspace builds to its own `target/`, so the
/// binary lives at `<repo>/rings/squads/target/deploy/zolana_squads_program.so`
/// relative to this crate's manifest (`<repo>/rings/squads/integration-tests`).
pub fn default_program_path() -> PathBuf {
    if let Ok(path) = std::env::var("SQUADS_RING_PROGRAM_PATH") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("target")
        .join("deploy")
        .join("zolana_squads_program.so")
}

/// Default location of the prebuilt SPP SBF binary, overridable with the
/// `SPP_PROGRAM_PATH` env var. Built via `just build-programs` (repo root),
/// which outputs to `<repo>/target/deploy/shielded_pool_program.so`.
pub fn default_spp_program_path() -> PathBuf {
    if let Ok(path) = std::env::var("SPP_PROGRAM_PATH") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("target")
        .join("deploy")
        .join("shielded_pool_program.so")
}

#[derive(Debug)]
pub enum ProgramTestError {
    MissingProgram(PathBuf),
    Litesvm(String),
    Io(std::io::Error),
}

impl std::fmt::Display for ProgramTestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProgramTestError::MissingProgram(path) => write!(
                f,
                "missing program binary at {path:?}. Build it with \
                 `cd rings/squads/program && cargo build-sbf --features bpf-entrypoint`, \
                 and the SPP with `just build-programs` from the repository root"
            ),
            ProgramTestError::Litesvm(msg) => write!(f, "litesvm failure: {msg}"),
            ProgramTestError::Io(err) => write!(f, "io: {err}"),
        }
    }
}

impl std::error::Error for ProgramTestError {}

impl From<std::io::Error> for ProgramTestError {
    fn from(err: std::io::Error) -> Self {
        ProgramTestError::Io(err)
    }
}

pub struct SquadsRingTest {
    pub svm: LiteSVM,
    pub payer: Keypair,
    pub program_id: Pubkey,
}

impl SquadsRingTest {
    /// A missing binary is a hard failure. A suite that silently skips reports
    /// green while proving nothing.
    pub fn new() -> Result<Self, ProgramTestError> {
        Self::with_program_path(&default_program_path())
    }

    pub fn with_program_path(path: &Path) -> Result<Self, ProgramTestError> {
        if !path.exists() {
            return Err(ProgramTestError::MissingProgram(path.to_path_buf()));
        }
        let program_id = Pubkey::new_from_array(SQUADS_RING_PROGRAM_ID);
        let mut svm = LiteSVM::new();
        let bytes = std::fs::read(path)?;
        svm.add_program(program_id, &bytes)
            .map_err(|e| ProgramTestError::Litesvm(format!("add_program: {e:?}")))?;

        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 10_000_000_000)
            .map_err(|e| ProgramTestError::Litesvm(format!("airdrop: {e:?}")))?;

        Ok(Self {
            svm,
            payer,
            program_id,
        })
    }

    /// Model the loader-v3 metadata written by `solana program deploy` while
    /// keeping LiteSVM's already-loaded executable in its program cache.
    /// Bootstrap tests use this to exercise the real upgrade-authority gate.
    pub fn install_upgradeable_deploy(
        &mut self,
        upgrade_authority: Option<&Pubkey>,
    ) -> Result<(), ProgramTestError> {
        let program_data = Pubkey::find_program_address(
            &[self.program_id.as_ref()],
            &BPF_LOADER_UPGRADEABLE_PUBKEY,
        )
        .0;

        let mut program_state = Vec::with_capacity(36);
        program_state.extend_from_slice(&2u32.to_le_bytes());
        program_state.extend_from_slice(program_data.as_ref());
        self.svm
            .set_account(
                self.program_id,
                Account {
                    lamports: 1_000_000_000,
                    data: program_state,
                    owner: BPF_LOADER_UPGRADEABLE_PUBKEY,
                    executable: true,
                    rent_epoch: 0,
                },
            )
            .map_err(|e| ProgramTestError::Litesvm(format!("set program metadata: {e:?}")))?;

        let mut program_data_state = Vec::with_capacity(45);
        program_data_state.extend_from_slice(&3u32.to_le_bytes());
        program_data_state.extend_from_slice(&0u64.to_le_bytes());
        match upgrade_authority {
            Some(authority) => {
                program_data_state.push(1);
                program_data_state.extend_from_slice(authority.as_ref());
            }
            None => program_data_state.push(0),
        }
        self.svm
            .set_account(
                program_data,
                Account {
                    lamports: 1_000_000_000,
                    data: program_data_state,
                    owner: BPF_LOADER_UPGRADEABLE_PUBKEY,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .map_err(|e| ProgramTestError::Litesvm(format!("set ProgramData: {e:?}")))
    }

    /// Load another program's binary, e.g. the real SPP so CPIs into it can
    /// execute. A missing binary is a hard failure.
    pub fn add_program(
        &mut self,
        program_id: &Pubkey,
        path: &Path,
    ) -> Result<(), ProgramTestError> {
        if !path.exists() {
            return Err(ProgramTestError::MissingProgram(path.to_path_buf()));
        }
        let bytes = std::fs::read(path)?;
        self.svm
            .add_program(*program_id, &bytes)
            .map_err(|e| ProgramTestError::Litesvm(format!("add_program: {e:?}")))
    }

    /// Move the SVM clock so an expiry check can be reached. LiteSVM starts at
    /// a fixed timestamp, which no `expiry` in a test ever passes.
    pub fn warp_unix_timestamp(&mut self, unix_timestamp: i64) {
        let mut clock: Clock = self.svm.get_sysvar();
        clock.unix_timestamp = unix_timestamp;
        self.svm.set_sysvar(&clock);
    }

    pub fn unix_timestamp(&self) -> i64 {
        self.svm.get_sysvar::<Clock>().unix_timestamp
    }

    pub fn airdrop(&mut self, pubkey: &Pubkey, lamports: u64) -> Result<(), ProgramTestError> {
        self.svm
            .airdrop(pubkey, lamports)
            .map(|_| ())
            .map_err(|e| ProgramTestError::Litesvm(format!("airdrop: {e:?}")))
    }

    pub fn rent_exempt(&self, data_len: usize) -> u64 {
        self.svm.minimum_balance_for_rent_exemption(data_len)
    }

    pub fn account_data(&self, pubkey: &Pubkey) -> Option<Vec<u8>> {
        self.svm.get_account(pubkey).map(|acc| acc.data)
    }

    pub fn lamports(&self, pubkey: &Pubkey) -> Option<u64> {
        self.svm.get_account(pubkey).map(|acc| acc.lamports)
    }

    /// Seed a program-owned account fixture to install state (e.g. a
    /// `ViewingKeyAccount`) that would otherwise require a proof to create.
    pub fn set_program_account(
        &mut self,
        address: &Pubkey,
        data: Vec<u8>,
    ) -> Result<(), ProgramTestError> {
        self.set_account_with_owner(address, data, self.program_id)
    }

    /// Seed an account fixture owned by an arbitrary program (e.g. the real
    /// SPP) to install cross-program state without the instruction flow that
    /// would normally create it.
    pub fn set_account_with_owner(
        &mut self,
        address: &Pubkey,
        data: Vec<u8>,
        owner: Pubkey,
    ) -> Result<(), ProgramTestError> {
        let lamports = self.rent_exempt(data.len());
        let account = Account {
            lamports,
            data,
            owner,
            executable: false,
            rent_epoch: 0,
        };
        self.svm
            .set_account(*address, account)
            .map_err(|e| ProgramTestError::Litesvm(format!("set_account: {e:?}")))
    }

    /// The payer is always a signer of the transaction it pays for. `signers`
    /// are appended after the payer.
    pub fn send(
        &mut self,
        ixs: &[Instruction],
        signers: &[&Keypair],
    ) -> Result<(), TransactionError> {
        let payer = self.payer.insecure_clone();
        let mut all_signers = Vec::with_capacity(signers.len() + 1);
        all_signers.push(&payer);
        all_signers.extend_from_slice(signers);

        let blockhash = self.svm.latest_blockhash();
        let message = Message::new(ixs, Some(&payer.pubkey()));
        let transaction = Transaction::new(&all_signers, message, blockhash);
        self.svm
            .send_transaction(transaction)
            .map(|_| ())
            .map_err(|meta| meta.err)
    }
}
