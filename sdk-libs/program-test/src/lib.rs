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
//! let root = rig.state_root(&tree.pubkey())?;
//! ```

use std::path::{Path, PathBuf};

use borsh::BorshSerialize;
use litesvm::LiteSVM;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use thiserror::Error;
use zolana_interface::{
    instruction::{
        tag, BatchUpdateAddressTreeData, CreatePoolTreeData, CreateProtocolConfigData,
        InsertAddressesData, PauseTreeData, ProoflessShieldData, TransactData,
        UpdateProtocolConfigData,
    },
    state::PROTOCOL_CONFIG_ACCOUNT_LEN,
    LIGHT_REGISTRY_PROGRAM_ID, SHIELDED_POOL_PROGRAM_ID,
};

pub mod registry_sdk;
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
        Self::with_program_path_and_payer(path, Keypair::new())
    }

    pub fn new_with_payer(payer: Keypair) -> Result<Self, RigError> {
        let program_path = default_program_path();
        Self::with_program_path_and_payer(&program_path, payer)
    }

    pub fn with_program_path_and_payer(path: &Path, payer: Keypair) -> Result<Self, RigError> {
        if !path.exists() {
            return Err(RigError::MissingProgram(path.to_path_buf()));
        }

        let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        let mut svm = LiteSVM::new();
        let program_bytes = std::fs::read(path)?;
        svm.add_program(program_id, &program_bytes)
            .map_err(|e| RigError::Litesvm(format!("add_program: {e:?}")))?;

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

    /// Allocate a fresh pool-tree account at the right size, fund it for
    /// rent-exemption, assign ownership to the shielded-pool program, then
    /// call `create_pool_tree`. Allocation is a top-level system_program
    /// instruction (NOT a CPI from inside shielded-pool) because Solana caps
    /// CPI reallocs at 10 KB and our combined account is ~1.16 MB.
    pub fn create_pool_tree(&mut self, account_size: u64) -> Result<Keypair, RigError> {
        self.create_pool_tree_with_size(account_size)
    }

    pub fn create_pool_tree_with_size(&mut self, account_size: u64) -> Result<Keypair, RigError> {
        let tree = Keypair::new();
        let create_ix = self.create_account_instruction(
            &self.payer.pubkey(),
            &tree.pubkey(),
            account_size,
            &self.program_id,
        );

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

        let payer = self.payer.insecure_clone();
        self.send(&[create_ix, pool_ix], &[&payer, &tree])?;
        Ok(tree)
    }

    pub fn create_program_owned_account(&mut self, account_size: u64) -> Result<Keypair, RigError> {
        let program_id = self.program_id;
        self.create_account_with_owner(account_size, program_id)
    }

    pub fn create_protocol_config_account(&mut self) -> Result<Keypair, RigError> {
        self.create_program_owned_account(PROTOCOL_CONFIG_ACCOUNT_LEN as u64)
    }

    pub fn create_account_with_owner(
        &mut self,
        account_size: u64,
        owner: Pubkey,
    ) -> Result<Keypair, RigError> {
        let account = Keypair::new();
        let create_ix = self.create_account_instruction(
            &self.payer.pubkey(),
            &account.pubkey(),
            account_size,
            &owner,
        );
        let payer = self.payer.insecure_clone();
        self.send(&[create_ix], &[&payer, &account])?;
        Ok(account)
    }

    fn create_account_instruction(
        &self,
        payer: &Pubkey,
        new_account: &Pubkey,
        account_size: u64,
        owner: &Pubkey,
    ) -> Instruction {
        let rent = self
            .svm
            .minimum_balance_for_rent_exemption(account_size as usize);

        // Top-level system_program::CreateAccount (discriminator 0).
        let mut create_data = vec![0u8; 4 + 8 + 8 + 32];
        create_data[4..12].copy_from_slice(&rent.to_le_bytes());
        create_data[12..20].copy_from_slice(&account_size.to_le_bytes());
        create_data[20..52].copy_from_slice(&owner.to_bytes());
        Instruction {
            program_id: solana_pubkey::Pubkey::default(),
            accounts: vec![
                AccountMeta::new(*payer, true),
                AccountMeta::new(*new_account, true),
            ],
            data: create_data,
        }
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

    pub fn update_protocol_config(
        &mut self,
        authority: &Keypair,
        new_authority: Option<&Keypair>,
        config: Option<registry_sdk::ProtocolConfig>,
    ) -> Result<(), RigError> {
        let new_authority_pubkey = new_authority.map(|keypair| keypair.pubkey());
        let ix = registry_sdk::build_update_protocol_config_ix(
            &authority.pubkey(),
            new_authority_pubkey.as_ref(),
            config,
        );
        let mut signers = vec![authority];
        if let Some(new_authority) = new_authority {
            if new_authority.pubkey() != authority.pubkey() {
                signers.push(new_authority);
            }
        }
        let payer = authority.pubkey();
        self.send_with_payer(&[ix], &signers, &payer)
    }

    pub fn update_forester_pda(
        &mut self,
        authority: &Keypair,
        derivation_key: &Pubkey,
        new_authority: Option<&Keypair>,
        config: Option<registry_sdk::ForesterConfig>,
    ) -> Result<(), RigError> {
        let new_authority_pubkey = new_authority.map(|keypair| keypair.pubkey());
        let ix = registry_sdk::build_update_forester_pda_ix(
            &authority.pubkey(),
            derivation_key,
            new_authority_pubkey.as_ref(),
            config,
        );
        let mut signers = vec![authority];
        if let Some(new_authority) = new_authority {
            if new_authority.pubkey() != authority.pubkey() {
                signers.push(new_authority);
            }
        }
        let payer = authority.pubkey();
        self.send_with_payer(&[ix], &signers, &payer)
    }

    pub fn update_forester_pda_weight(
        &mut self,
        protocol_authority: &Keypair,
        forester_authority: &Pubkey,
        new_weight: u64,
    ) -> Result<(), RigError> {
        let ix = registry_sdk::build_update_forester_pda_weight_ix(
            &protocol_authority.pubkey(),
            forester_authority,
            new_weight,
        );
        let payer = protocol_authority.pubkey();
        self.send_with_payer(&[ix], &[protocol_authority], &payer)
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

    pub fn report_work(&mut self, forester: &Keypair, epoch: u64) -> Result<(), RigError> {
        let ix = registry_sdk::build_report_work_ix(&forester.pubkey(), epoch);
        let payer = forester.pubkey();
        self.send_with_payer(&[ix], &[forester], &payer)
    }

    /// Submit `forest_address_tree` against the registry; the registry CPIs
    /// into shielded-pool's `batch_update_address_tree` with its CPI
    /// authority PDA as signer.
    pub fn forest_address_tree(
        &mut self,
        forester: &Keypair,
        pool_tree: &Pubkey,
        epoch: u64,
        data: BatchUpdateAddressTreeData,
    ) -> Result<(), RigError> {
        let ix =
            registry_sdk::build_forest_address_tree_ix(&forester.pubkey(), pool_tree, epoch, data);
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

    pub fn create_shielded_pool_protocol_config(
        &mut self,
        config: &Keypair,
        authority: &Keypair,
        data: CreateProtocolConfigData,
    ) -> Result<(), RigError> {
        let mut payload = vec![tag::CREATE_PROTOCOL_CONFIG];
        data.serialize(&mut payload).expect("infallible");
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new(config.pubkey(), false),
            ],
            data: payload,
        };
        self.send(&[ix], &[&self.payer.insecure_clone(), authority])
    }

    pub fn update_shielded_pool_protocol_config(
        &mut self,
        config: &Keypair,
        authority: &Keypair,
        data: UpdateProtocolConfigData,
    ) -> Result<(), RigError> {
        let mut payload = vec![tag::UPDATE_PROTOCOL_CONFIG];
        data.serialize(&mut payload).expect("infallible");
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new(config.pubkey(), false),
            ],
            data: payload,
        };
        self.send(&[ix], &[&self.payer.insecure_clone(), authority])
    }

    pub fn pause_tree(
        &mut self,
        config: &Keypair,
        tree: &Keypair,
        authority: &Keypair,
        data: PauseTreeData,
    ) -> Result<(), RigError> {
        let mut payload = vec![tag::PAUSE_TREE];
        data.serialize(&mut payload).expect("infallible");
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new_readonly(config.pubkey(), false),
                AccountMeta::new(tree.pubkey(), false),
            ],
            data: payload,
        };
        self.send(&[ix], &[&self.payer.insecure_clone(), authority])
    }

    pub fn transact(&mut self, tree: &Keypair, data: TransactData) -> Result<(), RigError> {
        self.transact_with_extra_accounts(tree, data, Vec::new())
    }

    pub fn transact_with_extra_accounts(
        &mut self,
        tree: &Keypair,
        data: TransactData,
        extra_accounts: Vec<AccountMeta>,
    ) -> Result<(), RigError> {
        let mut payload = vec![tag::TRANSACT];
        data.serialize(&mut payload).expect("infallible");
        let mut accounts = vec![
            AccountMeta::new(tree.pubkey(), false),
            AccountMeta::new_readonly(self.payer.pubkey(), true),
        ];
        accounts.extend(extra_accounts);
        let ix = Instruction {
            program_id: self.program_id,
            accounts,
            data: payload,
        };
        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        self.send(&[compute_budget_ix, ix], &[&self.payer.insecure_clone()])
    }

    /// Submits a proofless shield (tag 1): a public deposit that hashes and
    /// appends a UTXO with no proof. `extra_accounts` are the settlement
    /// accounts for the SOL/SPL deposit.
    pub fn proofless_shield(
        &mut self,
        tree: &Keypair,
        data: ProoflessShieldData,
        extra_accounts: Vec<AccountMeta>,
    ) -> Result<(), RigError> {
        let mut payload = vec![tag::PROOFLESS_SHIELD];
        data.serialize(&mut payload).expect("infallible");
        let mut accounts = vec![
            AccountMeta::new(tree.pubkey(), false),
            AccountMeta::new_readonly(self.payer.pubkey(), true),
        ];
        accounts.extend(extra_accounts);
        let ix = Instruction {
            program_id: self.program_id,
            accounts,
            data: payload,
        };
        let compute_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        self.send(&[compute_budget_ix, ix], &[&self.payer.insecure_clone()])
    }

    /// Read the raw bytes of any account in the rig.
    pub fn account_data(&self, pubkey: &Pubkey) -> Option<Vec<u8>> {
        self.svm.get_account(pubkey).map(|acc| acc.data)
    }

    pub fn send_instructions(
        &mut self,
        ixs: &[Instruction],
        signers: &[&Keypair],
    ) -> Result<(), RigError> {
        self.send(ixs, signers)
    }

    pub fn send_instructions_with_payer(
        &mut self,
        ixs: &[Instruction],
        signers: &[&Keypair],
        payer: &Pubkey,
    ) -> Result<(), RigError> {
        self.send_with_payer(ixs, signers, payer)
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
