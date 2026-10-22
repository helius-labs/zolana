use std::path::{Path, PathBuf};

use litesvm::LiteSVM;
use solana_account::Account;
use solana_instruction::Instruction;
use solana_instruction_error::InstructionError;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;
use zolana_squads_interface::SQUADS_RING_PROGRAM_ID;

/// The prover server URL, respecting `ZOLANA_PROVER_URL` (falling back to
/// `default`, normally `zolana_client::prover::SERVER_ADDRESS`) exactly like
/// `spawn_prover` does -- so `.prove(...)` calls target the same server
/// `spawn_prover` starts. Running `cargo test` directly does not auto-load
/// `.env`; see the repo `CLAUDE.md` "Per-clone port isolation" section.
pub fn prover_url(default: &str) -> String {
    std::env::var("ZOLANA_PROVER_URL").unwrap_or_else(|_| default.to_string())
}

/// Extract the custom program error code from a failed transaction's first
/// instruction error, or panic with the actual error.
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
    /// The program binary was not found; tests should skip rather than fail.
    MissingProgram(PathBuf),
    Litesvm(String),
    Io(std::io::Error),
}

impl std::fmt::Display for ProgramTestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProgramTestError::MissingProgram(path) => write!(
                f,
                "missing program binary at {path:?}; run \
                 `cd rings/squads/program && cargo build-sbf --features bpf-entrypoint`"
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

/// LiteSVM-based test environment for the Squads ring program.
pub struct SquadsRingTest {
    pub svm: LiteSVM,
    pub payer: Keypair,
    pub program_id: Pubkey,
}

impl SquadsRingTest {
    /// Boot a LiteSVM instance, fund a payer, and load the Squads ring program
    /// from the default path (or `SQUADS_RING_PROGRAM_PATH`).
    ///
    /// Returns `Ok(None)` when the program binary is missing so callers can skip
    /// cleanly rather than fail.
    pub fn new() -> Result<Option<Self>, ProgramTestError> {
        let path = default_program_path();
        if !path.exists() {
            eprintln!(
                "skipping squads-ring test: {} missing - run \
                 `cd rings/squads/program && cargo build-sbf --features bpf-entrypoint`",
                path.display()
            );
            return Ok(None);
        }
        Self::with_program_path(&path).map(Some)
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

    /// Load an additional program binary at `program_id` into the same LiteSVM
    /// instance (e.g. the real SPP, so CPIs into it can execute). Returns
    /// `Ok(false)` when the binary is missing so callers can skip cleanly.
    pub fn add_program(
        &mut self,
        program_id: &Pubkey,
        path: &Path,
    ) -> Result<bool, ProgramTestError> {
        if !path.exists() {
            return Ok(false);
        }
        let bytes = std::fs::read(path)?;
        self.svm
            .add_program(*program_id, &bytes)
            .map_err(|e| ProgramTestError::Litesvm(format!("add_program: {e:?}")))?;
        Ok(true)
    }

    /// Fund an arbitrary account with lamports.
    pub fn airdrop(&mut self, pubkey: &Pubkey, lamports: u64) -> Result<(), ProgramTestError> {
        self.svm
            .airdrop(pubkey, lamports)
            .map(|_| ())
            .map_err(|e| ProgramTestError::Litesvm(format!("airdrop: {e:?}")))
    }

    /// Minimum balance to make an account of `data_len` bytes rent-exempt.
    pub fn rent_exempt(&self, data_len: usize) -> u64 {
        self.svm.minimum_balance_for_rent_exemption(data_len)
    }

    /// Raw account data, or `None` if the account does not exist.
    pub fn account_data(&self, pubkey: &Pubkey) -> Option<Vec<u8>> {
        self.svm.get_account(pubkey).map(|acc| acc.data)
    }

    /// Lamport balance, or `None` if the account does not exist.
    pub fn lamports(&self, pubkey: &Pubkey) -> Option<u64> {
        self.svm.get_account(pubkey).map(|acc| acc.lamports)
    }

    /// Seed a program-owned account fixture at `address` with the given data,
    /// funded to rent-exemption. Used to install state (e.g. a
    /// `ViewingKeyAccount`) that would otherwise require a proof to create.
    pub fn set_program_account(
        &mut self,
        address: &Pubkey,
        data: Vec<u8>,
    ) -> Result<(), ProgramTestError> {
        self.set_account_with_owner(address, data, self.program_id)
    }

    /// Seed an account fixture at `address` owned by an arbitrary program
    /// (e.g. the real SPP), funded to rent-exemption. Used to install
    /// cross-program state without running the full instruction flow that
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

    /// The payer signs first; `signers` are appended. The payer is always a
    /// signer of the transaction it pays for.
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

/// Hash the exact forwarded SPP prefix and settlement accounts a ring proof binds.
pub fn spp_external_data_hash(
    instruction_tag: u8,
    spp: &zolana_interface::instruction::TransactIxData,
    accounts: &[solana_instruction::AccountMeta],
) -> [u8; 32] {
    use zolana_interface::instruction::instruction_data::transact::{
        settlement_accounts, ExternalDataPreimage, InterfaceTransfer, OwnerTag, TransactIxDataRef,
    };
    let bytes = spp.serialize().expect("serialize SPP payload");
    let (ix, prefix) = TransactIxDataRef::parse_with_external_data_prefix(&bytes)
        .expect("parse external-data prefix");
    let tag = [instruction_tag];
    let mut preimage = ExternalDataPreimage::new(&tag, prefix);
    let settlements = settlement_accounts(&ix.interface_transfers, ix.circuit, accounts)
        .expect("settlement accounts");
    let mut offset = 0;
    for transfer in &ix.interface_transfers {
        let group = &settlements[offset..offset + transfer.settlement_account_count()];
        let (asset, recipient) = match transfer {
            InterfaceTransfer::SolWithdrawal { .. } => (0, 1),
            InterfaceTransfer::SplWithdrawal { .. } => (1, 3),
            _ => panic!("expected withdrawal settlement"),
        };
        preimage
            .push_settlement(
                group[asset].pubkey.as_array(),
                group[recipient].pubkey.as_array(),
            )
            .expect("settlement suffix");
        offset += group.len();
    }
    for output in &ix.outputs {
        if let OwnerTag::Account(index) = output.owner_tag {
            preimage
                .push_owner_tag(
                    &output.owner_tag,
                    accounts[usize::from(index)].pubkey.as_array(),
                )
                .expect("owner suffix");
        }
    }
    preimage.finish().expect("external-data hash")
}
