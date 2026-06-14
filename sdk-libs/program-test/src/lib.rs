//! Litesvm-based test rig for the shielded-pool program.
//!
//! Boots a LiteSVM instance, loads the shielded-pool program, and exposes the
//! helpers used by integration tests.
//!
//! Usage:
//! ```ignore
//! use zolana_program_test::ShieldedPoolTestRig;
//! use zolana_interface::state::tree_account_size;
//! use solana_keypair::Keypair;
//!
//! let mut rig = ShieldedPoolTestRig::new()?;
//! let authority = Keypair::new();
//! rig.create_protocol_config(&authority)?;
//! let tree = rig.create_tree(tree_account_size() as u64, &authority)?;
//! let root = rig.state_root(&tree.pubkey())?;
//! ```

use std::path::{Path, PathBuf};

use litesvm::LiteSVM;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use thiserror::Error;
use zolana_interface::{
    state::state_root_offset, SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID,
};

mod admin;
pub mod events;
pub use events::{
    index_events, indexed_event_from_emit_payload, indexed_events_from_instructions,
    indexed_events_from_meta, parsed_instruction_from_compiled, single_proofless_shield_event,
    IndexedEvent, IndexedEventData, ParsedInstruction,
};
pub mod indexer;
pub use indexer::{IndexerError, PoolIndexer, UtxoRecord};
pub mod instructions;
pub use instructions::{
    create_protocol_config_instruction, create_tree_instructions, proofless_shield_sol_instruction,
    protocol_config_pda, rpc_state_root, system_create_account_ix, zone_auth_pda,
    zone_proofless_shield_sol_instruction, ZONE_TEST_PROGRAM_ID,
};
mod logging;
mod paths;
use paths::default_program_path;
mod proofless;
pub mod rpc;
#[cfg(feature = "solana-rpc")]
pub use rpc::SolanaRpc;
pub use rpc::{IndexedTransaction, Rpc, TestRpc};
mod spl;
mod wallet_data;
pub use wallet_data::proofless_event_for_wallet;
mod zone;

#[derive(Debug, Error)]
pub enum RigError {
    #[error("missing program binary at {0:?}; run `cargo build-sbf -p shielded-pool-program`")]
    MissingProgram(PathBuf),
    #[error("litesvm failure: {0}")]
    Litesvm(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("transaction: {0}")]
    Transaction(#[from] zolana_transaction::TransactionError),
    #[error("indexer: {0}")]
    Indexer(#[from] IndexerError),
    #[error("event: {0}")]
    Event(String),
    #[error("rpc: {0}")]
    Rpc(String),
}

pub struct ShieldedPoolTestRig {
    pub svm: LiteSVM,
    pub payer: Keypair,
    pub program_id: Pubkey,
    indexer: PoolIndexer,
}

impl ShieldedPoolTestRig {
    /// Boot a litesvm instance, fund a payer, and load the shielded-pool
    /// program from the default workspace `target/deploy/` location (or the
    /// `SHIELDED_POOL_PROGRAM_PATH` env override).
    pub fn new() -> Result<Self, RigError> {
        let program_path = default_program_path();
        Self::with_program_path(&program_path)
    }

    pub fn with_program_path(path: &Path) -> Result<Self, RigError> {
        if !path.exists() {
            return Err(RigError::MissingProgram(path.to_path_buf()));
        }

        let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        let mut svm = LiteSVM::new();
        let program_bytes = std::fs::read(path)?;
        svm.add_program(program_id, &program_bytes)
            .map_err(|e| RigError::Litesvm(format!("add_program: {e:?}")))?;

        let payer = Keypair::new();
        // Enough for the ~1.16 MB tree account rent.
        svm.airdrop(&payer.pubkey(), 20_000_000_000)
            .map_err(|e| RigError::Litesvm(format!("airdrop: {e:?}")))?;

        Ok(Self {
            svm,
            payer,
            program_id,
            indexer: PoolIndexer::new(),
        })
    }

    pub fn indexer(&self) -> &PoolIndexer {
        &self.indexer
    }

    pub(crate) fn rpc(&mut self) -> TestRpc<'_> {
        TestRpc::new(&mut self.svm, &mut self.indexer, self.program_id)
    }

    /// The shielded-pool CPI authority PDA, also the pool's SOL vault.
    pub fn cpi_authority(&self) -> Pubkey {
        Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY)
    }

    pub fn warp_to_slot(&mut self, slot: u64) -> Result<(), RigError> {
        self.svm.warp_to_slot(slot);
        Ok(())
    }

    pub fn airdrop(&mut self, pubkey: &Pubkey, lamports: u64) -> Result<(), RigError> {
        self.rpc().airdrop(pubkey, lamports).map(|_| ())
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

    /// Read the raw bytes of any account in the rig.
    pub fn account_data(&self, pubkey: &Pubkey) -> Option<Vec<u8>> {
        self.svm.get_account(pubkey).map(|acc| acc.data)
    }

    pub(crate) fn send(
        &mut self,
        ixs: &[Instruction],
        signers: &[&Keypair],
    ) -> Result<(), RigError> {
        self.send_indexed(ixs, signers).map(|_| ())
    }

    pub(crate) fn send_indexed(
        &mut self,
        ixs: &[Instruction],
        signers: &[&Keypair],
    ) -> Result<IndexedTransaction, RigError> {
        let payer = self.payer.insecure_clone();
        let payer_pubkey = payer.pubkey();
        let mut all_signers = Vec::with_capacity(signers.len() + 1);
        all_signers.push(&payer);
        all_signers.extend_from_slice(signers);
        self.rpc()
            .send_instructions(ixs, &all_signers, &payer_pubkey)
    }
}
