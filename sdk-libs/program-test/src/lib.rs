//! Litesvm-based program-test environment for Zolana protocol programs.
//!
//! Boots a LiteSVM instance, loads the shielded-pool program, and exposes the
//! helpers used by integration tests.
//!
//! Usage:
//! ```ignore
//! use zolana_program_test::ZolanaProgramTest;
//! use zolana_interface::state::tree_account_size;
//! use solana_keypair::Keypair;
//!
//! let mut test = ZolanaProgramTest::new()?;
//! let authority = Keypair::new();
//! test.create_protocol_config(&authority)?;
//! let tree = test.create_tree(tree_account_size() as u64, &authority)?;
//! let root = test.state_root(&tree.pubkey())?;
//! ```

use std::path::{Path, PathBuf};

use litesvm::LiteSVM;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::ClientError;
use zolana_interface::{state::state_root_offset, SHIELDED_POOL_PROGRAM_ID};

mod admin;
pub mod events;
pub use events::{
    deposit_output_from_event, deposit_outputs_from_event, index_events, indexed_events_from_meta,
    parsed_instruction_from_compiled, parsed_instruction_groups_from_meta,
    ring_deposit_output_from_event, ring_deposit_outputs_from_event, single_deposit_view,
    DepositOutput, IndexedEvent, InstructionGroup, ParsedInstruction, RingDepositOutput,
};
pub mod indexer;
pub use indexer::{
    shielded_transaction_from_general_event, IndexedPayload, IndexedUtxo, IndexerError,
    ProoflessOutput, TestIndexer,
};
pub mod instructions;
pub use instructions::{
    create_tree_instructions, rpc_state_root, system_create_account_ix, RING_TEST_PROGRAM_ID,
};
mod paths;
mod rejection;
use paths::default_program_path;
mod proofless;
pub use proofless::DepositBatch;
pub mod rpc;
pub use rejection::Rejection;
pub use rpc::IndexedTransaction;
mod transaction_trace;
pub use transaction_trace::{
    AccountSnapshot, AccountTransition, InstructionTrace, TransactionOutcome, TransactionTrace,
};
pub use zolana_client::Rpc;
mod ring;
mod spl;
mod wallet_data;
pub use ring::RingDepositBatch;

/// Build the canonical 32-byte field representation of a repeated legacy
/// 31-byte test blinding.
pub fn test_blinding(byte: u8) -> [u8; 32] {
    let mut blinding = [byte; 32];
    blinding[0] = 0;
    blinding
}

#[derive(Debug, Error)]
pub enum ProgramTestError {
    #[error("missing program binary at {0:?}; run `cargo build-sbf -p shielded-pool-program`")]
    MissingProgram(PathBuf),
    #[error("litesvm failure: {0}")]
    Litesvm(String),
    #[error("transaction failed: {0:?}")]
    TransactionFailure(Box<litesvm::types::FailedTransactionMetadata>),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("transaction: {0}")]
    Transaction(#[from] zolana_transaction::TransactionError),
    #[error("deposit builder: {0}")]
    DepositBuild(#[from] zolana_interface::instruction::DepositBuildError),
    #[error("indexer: {0}")]
    Indexer(#[from] IndexerError),
    #[error("event: {0}")]
    Event(String),
    #[error("rpc: {0}")]
    Rpc(String),
    #[error("pubkey: {0}")]
    Pubkey(#[from] solana_pubkey::PubkeyError),
}

impl From<ClientError> for ProgramTestError {
    fn from(e: ClientError) -> Self {
        ProgramTestError::Rpc(e.to_string())
    }
}

impl From<litesvm::types::FailedTransactionMetadata> for ProgramTestError {
    fn from(error: litesvm::types::FailedTransactionMetadata) -> Self {
        Self::TransactionFailure(Box::new(error))
    }
}

pub struct ZolanaProgramTest {
    pub svm: LiteSVM,
    pub payer: Keypair,
    pub program_id: Pubkey,
    indexer: TestIndexer,
    /// Counter mixed into deterministic tree seeds so repeated `create_tree`
    /// calls produce distinct reproducible addresses.
    tree_counter: u64,
    transaction_traces: Vec<TransactionTrace>,
}

impl ZolanaProgramTest {
    /// Boot a litesvm instance, fund a payer, and load the shielded-pool
    /// program from the default workspace `target/deploy/` location (or the
    /// `SHIELDED_POOL_PROGRAM_PATH` env override).
    pub fn new() -> Result<Self, ProgramTestError> {
        let program_path = default_program_path();
        Self::with_program_path(&program_path)
    }

    pub fn with_program_path(path: &Path) -> Result<Self, ProgramTestError> {
        Self::with_svm_and_program_path(LiteSVM::new(), path)
    }

    /// [`Self::with_program_path`] over a caller-prepared `LiteSVM`, for
    /// harnesses that must install custom syscalls before `add_program`.
    pub fn with_svm_and_program_path(
        mut svm: LiteSVM,
        path: &Path,
    ) -> Result<Self, ProgramTestError> {
        if !path.exists() {
            return Err(ProgramTestError::MissingProgram(path.to_path_buf()));
        }

        let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        let program_bytes = std::fs::read(path)?;
        svm.add_program(program_id, &program_bytes)
            .map_err(|e| ProgramTestError::Litesvm(format!("add_program: {e:?}")))?;

        let payer = Keypair::new();
        // Enough for the ~1.16 MB tree account rent.
        svm.airdrop(&payer.pubkey(), 20_000_000_000)
            .map_err(|e| ProgramTestError::Litesvm(format!("airdrop: {e:?}")))?;

        Ok(Self {
            svm,
            payer,
            program_id,
            indexer: TestIndexer::new(),
            tree_counter: 0,
            transaction_traces: Vec::new(),
        })
    }

    /// Deterministic signer for a new tree account.
    pub(crate) fn next_tree_keypair(&mut self) -> Keypair {
        let mut seed = [0u8; 32];
        seed[..16].copy_from_slice(b"zolana_pool_tree");
        seed[24..].copy_from_slice(&self.tree_counter.to_le_bytes());
        self.tree_counter += 1;
        Keypair::new_from_array(seed)
    }

    pub fn indexer(&self) -> &TestIndexer {
        &self.indexer
    }

    /// All submissions made through this backend, including rejected ones.
    pub fn transaction_traces(&self) -> &[TransactionTrace] {
        &self.transaction_traces
    }

    /// Diagnostics and automatic pre/post snapshots for the last submission.
    pub fn last_transaction_trace(&self) -> Option<&TransactionTrace> {
        self.transaction_traces.last()
    }

    pub fn warp_to_slot(&mut self, slot: u64) -> Result<(), ProgramTestError> {
        self.svm.warp_to_slot(slot);
        Ok(())
    }

    pub fn airdrop(&mut self, pubkey: &Pubkey, lamports: u64) -> Result<(), ProgramTestError> {
        // Deliberately does NOT expire the blockhash: LiteSVM accepts only the
        // single current latest_blockhash, so expiring here would invalidate any
        // transaction signed before the airdrop (`BlockhashNotFound`). Freshness
        // against AlreadyProcessed dedup lives in the signing path
        // (`create_and_send_transaction` expires immediately before fetching the
        // blockhash for a new transaction).
        self.svm
            .airdrop(pubkey, lamports)
            .map(|_| ())
            .map_err(ProgramTestError::from)
    }

    /// The on-chain state sub-tree root of a pool tree account.
    pub fn state_root(&self, tree: &Pubkey) -> Option<[u8; 32]> {
        let data = self.account_data(tree)?;
        let offset = state_root_offset();
        let slice = data.get(offset..offset + 32)?;
        let mut root = [0u8; 32];
        root.copy_from_slice(slice);
        Some(root)
    }

    /// Read the raw bytes of any account in the test environment.
    pub fn account_data(&self, pubkey: &Pubkey) -> Option<Vec<u8>> {
        self.svm.get_account(pubkey).map(|acc| acc.data)
    }

    pub fn create_and_send_default_payer_transaction(
        &mut self,
        ixs: &[Instruction],
        signers: &[&Keypair],
    ) -> Result<IndexedTransaction, ProgramTestError> {
        let payer = self.payer.insecure_clone();
        let payer_pubkey = payer.pubkey();
        let mut all_signers = Vec::with_capacity(signers.len() + 1);
        all_signers.push(&payer);
        all_signers.extend_from_slice(signers);
        self.create_and_send_transaction(ixs, &payer_pubkey, &all_signers)
    }

    pub(crate) fn send(
        &mut self,
        ixs: &[Instruction],
        signers: &[&Keypair],
    ) -> Result<(), ProgramTestError> {
        self.create_and_send_default_payer_transaction(ixs, signers)
            .map(|_| ())
    }
}
