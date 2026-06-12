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
//! let tree = rig.create_tree()?;
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
        encode_instruction, tag, BatchUpdateAddressTreeData, CreateTreeData,
        CreateProtocolConfigData, ProoflessShieldIxData, ProoflessShieldEvent,
    },
    LIGHT_REGISTRY_PROGRAM_ID, SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID,
    SPP_PROTOCOL_CONFIG_PDA_SEED,
};

pub mod indexer;
pub mod registry_sdk;
pub use indexer::{PoolIndexer, UtxoRecord};
pub use registry_sdk::{ForesterConfig, ProtocolConfig};

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

/// Default location of `light_registry.so`: `<workspace>/target/deploy/`.
/// Overridable via `LIGHT_REGISTRY_PROGRAM_PATH` env var, mirroring the
/// shielded-pool path resolution above.
fn default_registry_program_path() -> PathBuf {
    if let Ok(p) = std::env::var("LIGHT_REGISTRY_PROGRAM_PATH") {
        return PathBuf::from(p);
    }
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("..")
        .join("..")
        .join("target")
        .join("deploy")
        .join("light_registry.so")
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
        // ~20 SOL — the combined pool-tree account is ~1.16 MB which costs
        // ~8 SOL rent-exempt, so a 1 SOL airdrop is too small.
        svm.airdrop(&payer.pubkey(), 20_000_000_000)
            .map_err(|e| RigError::Litesvm(format!("airdrop: {e:?}")))?;

        Ok(Self {
            svm,
            payer,
            program_id,
        })
    }

    /// The canonical protocol-config PDA for the shielded-pool program.
    pub fn protocol_config_pda(&self) -> Pubkey {
        Pubkey::find_program_address(&[SPP_PROTOCOL_CONFIG_PDA_SEED], &self.program_id).0
    }

    /// The shielded-pool CPI authority PDA — also the pool's SOL vault.
    pub fn cpi_authority(&self) -> Pubkey {
        Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY)
    }

    /// Create the canonical protocol config naming `authority`. The authority
    /// signs and pays the PDA rent, so it is funded here.
    pub fn create_protocol_config(&mut self, authority: &Keypair) -> Result<Pubkey, RigError> {
        self.airdrop(&authority.pubkey(), 1_000_000_000)?;
        let config = self.protocol_config_pda();
        let data = encode_instruction(
            tag::CREATE_PROTOCOL_CONFIG,
            &CreateProtocolConfigData {
                authority: authority.pubkey().to_bytes(),
            },
        );
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new(config, false),
                AccountMeta::new_readonly(Pubkey::default(), false),
            ],
            data,
        };
        self.send(&[ix], &[&self.payer.insecure_clone(), authority])?;
        Ok(config)
    }

    /// Allocate a fresh pool-tree account at the right size, fund it for
    /// rent-exemption, assign ownership to the shielded-pool program, then
    /// call `create_tree` signed by the protocol-config authority.
    /// Allocation is a top-level system_program instruction (NOT a CPI from
    /// inside shielded-pool) because Solana caps CPI reallocs at 10 KB and our
    /// combined account is ~1.16 MB.
    pub fn create_tree(
        &mut self,
        account_size: u64,
        authority: &Keypair,
    ) -> Result<Keypair, RigError> {
        let tree = Keypair::new();
        let rent = self
            .svm
            .minimum_balance_for_rent_exemption(account_size as usize);

        // 1. Top-level system_program::CreateAccount (discriminator 0).
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

        // 2. Call create_tree: [authority(signer), protocol_config, tree].
        let mut create_pool_data = vec![tag::CREATE_TREE];
        CreateTreeData
            .serialize(&mut create_pool_data)
            .expect("infallible");
        let pool_ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new_readonly(self.protocol_config_pda(), false),
                AccountMeta::new(tree.pubkey(), false),
            ],
            data: create_pool_data,
        };

        self.send(
            &[create_ix, pool_ix],
            &[&self.payer.insecure_clone(), &tree, authority],
        )?;
        Ok(tree)
    }

    /// A SOL-deposit `ProoflessShieldIxData` with bare commitment fields.
    pub fn sol_shield_data(lamports: u64, owner_utxo_hash: [u8; 32]) -> ProoflessShieldIxData {
        ProoflessShieldIxData {
            view_tag: [0u8; 32],
            owner_utxo_hash,
            salt: [0u8; 16],
            public_sol_amount: Some(lamports),
            public_spl_amount: None,
            policy_data_hash: None,
            zone_data: None,
            program_data_hash: None,
            program_data: None,
            cpi_signer: None,
        }
    }

    /// Send a `proofless_shield` carrying `data` and return the
    /// `ProoflessShieldEvent` it emitted via self-CPI — read from the inner
    /// instructions exactly the way an indexer authenticates events. SOL
    /// deposits only: the depositor signs and is the SOL source.
    /// Accounts: [tree, signer, system_program, cpi_authority,
    /// user_sol_account, shielded_pool_program].
    pub fn proofless_shield(
        &mut self,
        tree: &Keypair,
        depositor: &Keypair,
        data: &ProoflessShieldIxData,
    ) -> Result<ProoflessShieldEvent, RigError> {
        let encoded = encode_instruction(tag::PROOFLESS_SHIELD, data);
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(tree.pubkey(), false),
                AccountMeta::new(depositor.pubkey(), true),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new(self.cpi_authority(), false),
                AccountMeta::new(depositor.pubkey(), false),
                AccountMeta::new_readonly(self.program_id, false),
            ],
            data: encoded,
        };

        let payer = self.payer.pubkey();
        let message = Message::new(&[ix], Some(&payer));
        let account_keys = message.account_keys.clone();
        let blockhash = self.svm.latest_blockhash();
        let tx = Transaction::new(
            &[&self.payer.insecure_clone(), depositor],
            message,
            blockhash,
        );
        let meta = self
            .svm
            .send_transaction(tx)
            .map_err(|e| RigError::Litesvm(format!("send_transaction: {e:?}")))?;

        // The event is the inner emit_event instruction invoked by the
        // shielded-pool program itself.
        for inner in meta.inner_instructions.iter().flatten() {
            let compiled = &inner.instruction;
            let program = account_keys
                .get(compiled.program_id_index as usize)
                .copied()
                .unwrap_or_default();
            if program == self.program_id
                && compiled.data.first() == Some(&tag::EMIT_EVENT)
            {
                return borsh::BorshDeserialize::try_from_slice(&compiled.data[1..])
                    .map_err(|e| RigError::Litesvm(format!("event decode: {e}")));
            }
        }
        Err(RigError::Litesvm("no emit_event inner instruction".into()))
    }

    /// Deposit `lamports` of SOL without a proof (`proofless_shield`). The
    /// UTXO commits to the opaque `owner_utxo_hash`.
    pub fn proofless_shield_sol(
        &mut self,
        tree: &Keypair,
        depositor: &Keypair,
        lamports: u64,
        owner_utxo_hash: [u8; 32],
    ) -> Result<ProoflessShieldEvent, RigError> {
        let data = Self::sol_shield_data(lamports, owner_utxo_hash);
        self.proofless_shield(tree, depositor, &data)
    }

    /// Load `light_registry.so` into this rig in addition to shielded-pool.
    /// Required before calling the registry-setup or `forest_address_tree`
    /// helpers.
    pub fn load_registry(&mut self) -> Result<(), RigError> {
        self.load_registry_from(&default_registry_program_path())
    }

    pub fn load_registry_from(&mut self, path: &Path) -> Result<(), RigError> {
        if !path.exists() {
            return Err(RigError::MissingProgram(path.to_path_buf()));
        }
        let bytes = std::fs::read(path)?;
        let id = Pubkey::new_from_array(LIGHT_REGISTRY_PROGRAM_ID);
        self.svm
            .add_program(id, &bytes)
            .map_err(|e| RigError::Litesvm(format!("add_registry: {e:?}")))?;
        Ok(())
    }

    pub fn initialize_protocol_config(
        &mut self,
        authority: &Keypair,
        config: registry_sdk::ProtocolConfig,
    ) -> Result<(), RigError> {
        let ix = registry_sdk::build_initialize_protocol_config_ix(
            &self.payer.pubkey(),
            &authority.pubkey(),
            config,
        );
        self.send(&[ix], &[&self.payer.insecure_clone(), authority])
    }

    pub fn register_forester(
        &mut self,
        governance_authority: &Keypair,
        forester_authority: &Pubkey,
        config: registry_sdk::ForesterConfig,
        weight: Option<u64>,
    ) -> Result<(), RigError> {
        let ix = registry_sdk::build_register_forester_ix(
            &self.payer.pubkey(),
            &governance_authority.pubkey(),
            forester_authority,
            config,
            weight,
        );
        self.send(&[ix], &[&self.payer.insecure_clone(), governance_authority])
    }

    pub fn register_forester_epoch(
        &mut self,
        forester: &Keypair,
        epoch: u64,
    ) -> Result<(), RigError> {
        let ix = registry_sdk::build_register_forester_epoch_ix(&forester.pubkey(), epoch);
        let payer = forester.pubkey();
        self.send_with_payer(&[ix], &[forester], &payer)
    }

    pub fn finalize_registration(
        &mut self,
        forester: &Keypair,
        epoch: u64,
    ) -> Result<(), RigError> {
        let ix = registry_sdk::build_finalize_registration_ix(&forester.pubkey(), epoch);
        let payer = forester.pubkey();
        self.send_with_payer(&[ix], &[forester], &payer)
    }

    /// Submit `forest_address_tree` against the registry; the registry CPIs
    /// into shielded-pool's `batch_update_address_tree` with its CPI
    /// authority PDA as signer.
    pub fn forest_address_tree(
        &mut self,
        forester: &Keypair,
        tree: &Pubkey,
        epoch: u64,
        data: BatchUpdateAddressTreeData,
    ) -> Result<(), RigError> {
        let ix =
            registry_sdk::build_forest_address_tree_ix(&forester.pubkey(), tree, epoch, data);
        let payer = forester.pubkey();
        self.send_with_payer(&[ix], &[forester], &payer)
    }

    pub fn warp_to_slot(&mut self, slot: u64) -> Result<(), RigError> {
        self.svm.warp_to_slot(slot);
        Ok(())
    }

    pub fn airdrop(&mut self, pubkey: &Pubkey, lamports: u64) -> Result<(), RigError> {
        self.svm
            .airdrop(pubkey, lamports)
            .map_err(|e| RigError::Litesvm(format!("airdrop: {e:?}")))?;
        Ok(())
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
    /// The on-chain state sub-tree root of a pool tree account.
    pub fn state_root(&self, tree: &Pubkey) -> Option<[u8; 32]> {
        let data = self.account_data(tree)?;
        let offset = shielded_pool_program::instructions::create_tree::init::state_root_offset();
        let slice = data.get(offset..offset + 32)?;
        let mut root = [0u8; 32];
        root.copy_from_slice(slice);
        Some(root)
    }

    pub fn account_data(&self, pubkey: &Pubkey) -> Option<Vec<u8>> {
        self.svm.get_account(pubkey).map(|acc| acc.data)
    }

    fn send(&mut self, ixs: &[Instruction], signers: &[&Keypair]) -> Result<(), RigError> {
        let payer = self.payer.pubkey();
        self.send_with_payer(ixs, signers, &payer)
    }

    fn send_with_payer(
        &mut self,
        ixs: &[Instruction],
        signers: &[&Keypair],
        payer: &Pubkey,
    ) -> Result<(), RigError> {
        let blockhash = self.svm.latest_blockhash();
        let msg = Message::new(ixs, Some(payer));
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
