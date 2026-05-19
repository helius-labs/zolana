//! Litesvm-based test rig for the shielded-pool program.
//!
//! Boots a litesvm instance, loads the shielded-pool program (.so), and
//! exposes one-call helpers for every shielded-pool instruction plus state
//! accessors used by integration tests.
//!
//! Usage:
//! ```ignore
//! use light_program_test::PoolTestRig;
//!
//! let mut rig = PoolTestRig::new()?;
//! let tree = rig.create_pool_tree()?;
//! rig.append_state_leaves(&tree, vec![[1u8; 32]])?;
//! let root = rig.state_root(&tree.pubkey())?;
//! ```

use std::path::{Path, PathBuf};

use borsh::BorshSerialize;
use litesvm::LiteSVM;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use thiserror::Error;
use zolana_interface::{
    instruction::{
        tag, AppendStateLeavesData, BatchUpdateAddressTreeData, CreatePoolTreeData,
        InsertAddressesData,
    },
    SHIELDED_POOL_PROGRAM_ID,
};

#[derive(Debug, Error)]
pub enum RigError {
    #[error("missing program binary at {0:?}; run `cargo build-sbf -p shielded-pool-program`")]
    MissingProgram(PathBuf),
    #[error("litesvm failure: {0}")]
    Litesvm(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub struct PoolTestRig {
    pub svm: LiteSVM,
    pub payer: Keypair,
    pub program_id: Pubkey,
}

impl PoolTestRig {
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
        svm.airdrop(&payer.pubkey(), 1_000_000_000)
            .map_err(|e| RigError::Litesvm(format!("airdrop: {e:?}")))?;

        Ok(Self {
            svm,
            payer,
            program_id,
        })
    }

    /// Allocate a fresh pool-tree account at the right size, transfer rent,
    /// assign ownership to the shielded-pool program, then call
    /// `create_pool_tree`. Returns the tree account keypair.
    pub fn create_pool_tree(&mut self, account_size: u64) -> Result<Keypair, RigError> {
        let tree = Keypair::new();
        let rent = self
            .svm
            .minimum_balance_for_rent_exemption(account_size as usize);

        // 1. Create + assign via system_program (discriminator 0).
        let mut create_data = vec![0u8; 4 + 8 + 8 + 32];
        create_data[4..12].copy_from_slice(&rent.to_le_bytes());
        create_data[12..20].copy_from_slice(&account_size.to_le_bytes());
        create_data[20..52].copy_from_slice(&self.program_id.to_bytes());
        let create_ix = Instruction {
            program_id: solana_pubkey::Pubkey::default(),
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new(tree.pubkey(), true),
            ],
            data: create_data,
        };

        // 2. Call create_pool_tree.
        let mut create_pool_data = vec![tag::CREATE_POOL_TREE];
        CreatePoolTreeData
            .serialize(&mut create_pool_data)
            .expect("infallible");
        let pool_ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new(tree.pubkey(), false),
            ],
            data: create_pool_data,
        };

        self.send(
            &[create_ix, pool_ix],
            &[&self.payer.insecure_clone(), &tree],
        )?;
        Ok(tree)
    }

    pub fn append_state_leaves(
        &mut self,
        tree: &Keypair,
        leaves: Vec<[u8; 32]>,
    ) -> Result<(), RigError> {
        let mut data = vec![tag::APPEND_STATE_LEAVES];
        AppendStateLeavesData { leaves }
            .serialize(&mut data)
            .expect("infallible");
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(self.payer.pubkey(), true),
                AccountMeta::new(tree.pubkey(), false),
            ],
            data,
        };
        self.send(&[ix], &[&self.payer.insecure_clone()])
    }

    pub fn insert_addresses(
        &mut self,
        tree: &Keypair,
        addresses: Vec<[u8; 32]>,
    ) -> Result<(), RigError> {
        let mut data = vec![tag::INSERT_ADDRESSES];
        InsertAddressesData { addresses }
            .serialize(&mut data)
            .expect("infallible");
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(self.payer.pubkey(), true),
                AccountMeta::new(tree.pubkey(), false),
            ],
            data,
        };
        self.send(&[ix], &[&self.payer.insecure_clone()])
    }

    pub fn batch_update_address_tree(
        &mut self,
        tree: &Keypair,
        data: BatchUpdateAddressTreeData,
    ) -> Result<(), RigError> {
        let mut payload = vec![tag::BATCH_UPDATE_ADDRESS_TREE];
        data.serialize(&mut payload).expect("infallible");
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(self.payer.pubkey(), true),
                AccountMeta::new(tree.pubkey(), false),
            ],
            data: payload,
        };
        self.send(&[ix], &[&self.payer.insecure_clone()])
    }

    /// Read the raw bytes of any account in the rig.
    pub fn account_data(&self, pubkey: &Pubkey) -> Option<Vec<u8>> {
        self.svm.get_account(pubkey).map(|acc| acc.data)
    }

    fn send(&mut self, ixs: &[Instruction], signers: &[&Keypair]) -> Result<(), RigError> {
        let blockhash = self.svm.latest_blockhash();
        let msg = Message::new(ixs, Some(&self.payer.pubkey()));
        let tx = Transaction::new(signers, msg, blockhash);
        self.svm
            .send_transaction(tx)
            .map(|_| ())
            .map_err(|e| RigError::Litesvm(format!("send_transaction: {e:?}")))
    }
}

fn default_program_path() -> PathBuf {
    if let Ok(p) = std::env::var("SHIELDED_POOL_PROGRAM_PATH") {
        return PathBuf::from(p);
    }
    // CARGO_MANIFEST_DIR points at sdk-libs/program-test at build time; the
    // workspace root is two levels up.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("..")
        .join("..")
        .join("target")
        .join("deploy")
        .join("shielded_pool_program.so")
}
