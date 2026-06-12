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
        encode_instruction, tag, BatchUpdateAddressTreeData, CpiSignerData,
        CreateSplInterfaceData, CreateTreeData, CreateProtocolConfigData, PauseTreeData,
        ProoflessShieldEvent, ProoflessShieldIxData, UpdateProtocolConfigData,
        ZoneProoflessShieldIxData,
    },
    LIGHT_REGISTRY_PROGRAM_ID, SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID,
    SPL_ASSET_COUNTER_PDA_SEED, SPL_ASSET_REGISTRY_PDA_SEED, SPL_ASSET_VAULT_PDA_SEED,
    SPL_TOKEN_PROGRAM_ID, SPP_PROTOCOL_CONFIG_PDA_SEED,
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

    /// The SPL token program (litesvm preloads it).
    pub fn token_program_id() -> Pubkey {
        Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID)
    }

    pub fn spl_asset_counter_pda(&self) -> Pubkey {
        Pubkey::find_program_address(&[SPL_ASSET_COUNTER_PDA_SEED], &self.program_id).0
    }

    /// The per-mint asset registry PDA (spec: `spl_asset_registry`).
    pub fn spl_asset_registry_pda(&self, mint: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(
            &[SPL_ASSET_REGISTRY_PDA_SEED, mint.as_ref()],
            &self.program_id,
        )
        .0
    }

    /// The per-mint pool vault PDA (spec: `spl_token_interface`).
    pub fn spl_asset_vault_pda(&self, mint: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(&[SPL_ASSET_VAULT_PDA_SEED, mint.as_ref()], &self.program_id)
            .0
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

    /// Rotate the protocol-config authority. Accounts: [authority(signer), config].
    pub fn update_protocol_config(
        &mut self,
        authority: &Keypair,
        new_authority: &Pubkey,
    ) -> Result<(), RigError> {
        let data = encode_instruction(
            tag::UPDATE_PROTOCOL_CONFIG,
            &UpdateProtocolConfigData {
                new_authority: new_authority.to_bytes(),
            },
        );
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new(self.protocol_config_pda(), false),
            ],
            data,
        };
        self.send(&[ix], &[&self.payer.insecure_clone(), authority])
    }

    /// Pause or unpause a tree. Accounts: [authority(signer), config, tree].
    pub fn pause_tree(
        &mut self,
        authority: &Keypair,
        tree: &Keypair,
        paused: bool,
    ) -> Result<(), RigError> {
        let data = encode_instruction(tag::PAUSE_TREE, &PauseTreeData { paused });
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new_readonly(self.protocol_config_pda(), false),
                AccountMeta::new(tree.pubkey(), false),
            ],
            data,
        };
        self.send(&[ix], &[&self.payer.insecure_clone(), authority])
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

        // 1. Top-level system_program::CreateAccount.
        let create_ix = system_create_account_ix(
            &self.payer.pubkey(),
            &tree.pubkey(),
            rent,
            account_size,
            &self.program_id,
        );

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
            program_data_hash: None,
            program_data: None,
            cpi_signer: None,
        }
    }

    /// An SPL-deposit `ProoflessShieldIxData` with bare commitment fields.
    pub fn spl_shield_data(amount: u64, owner_utxo_hash: [u8; 32]) -> ProoflessShieldIxData {
        ProoflessShieldIxData {
            view_tag: [0u8; 32],
            owner_utxo_hash,
            salt: [0u8; 16],
            public_sol_amount: None,
            public_spl_amount: Some(amount),
            program_data_hash: None,
            program_data: None,
            cpi_signer: None,
        }
    }

    /// Create a mint with the rig payer as mint authority (decimals 9).
    pub fn create_mint(&mut self) -> Result<Pubkey, RigError> {
        const MINT_LEN: u64 = 82;
        const INITIALIZE_MINT2: u8 = 20;
        let mint = Keypair::new();
        let rent = self
            .svm
            .minimum_balance_for_rent_exemption(MINT_LEN as usize);
        let create_ix = system_create_account_ix(
            &self.payer.pubkey(),
            &mint.pubkey(),
            rent,
            MINT_LEN,
            &Self::token_program_id(),
        );
        let mut data = vec![INITIALIZE_MINT2, 9];
        data.extend_from_slice(&self.payer.pubkey().to_bytes());
        data.push(0); // no freeze authority
        let init_ix = Instruction {
            program_id: Self::token_program_id(),
            accounts: vec![AccountMeta::new(mint.pubkey(), false)],
            data,
        };
        self.send(&[create_ix, init_ix], &[&self.payer.insecure_clone(), &mint])?;
        Ok(mint.pubkey())
    }

    /// Create a token account for `mint` owned by `owner`.
    pub fn create_token_account(
        &mut self,
        mint: &Pubkey,
        owner: &Pubkey,
    ) -> Result<Pubkey, RigError> {
        const TOKEN_ACCOUNT_LEN: u64 = 165;
        const INITIALIZE_ACCOUNT3: u8 = 18;
        let account = Keypair::new();
        let rent = self
            .svm
            .minimum_balance_for_rent_exemption(TOKEN_ACCOUNT_LEN as usize);
        let create_ix = system_create_account_ix(
            &self.payer.pubkey(),
            &account.pubkey(),
            rent,
            TOKEN_ACCOUNT_LEN,
            &Self::token_program_id(),
        );
        let mut data = vec![INITIALIZE_ACCOUNT3];
        data.extend_from_slice(&owner.to_bytes());
        let init_ix = Instruction {
            program_id: Self::token_program_id(),
            accounts: vec![
                AccountMeta::new(account.pubkey(), false),
                AccountMeta::new_readonly(*mint, false),
            ],
            data,
        };
        self.send(
            &[create_ix, init_ix],
            &[&self.payer.insecure_clone(), &account],
        )?;
        Ok(account.pubkey())
    }

    /// Mint `amount` tokens to `account` (the rig payer is the mint authority).
    pub fn mint_to(
        &mut self,
        mint: &Pubkey,
        account: &Pubkey,
        amount: u64,
    ) -> Result<(), RigError> {
        const MINT_TO: u8 = 7;
        let mut data = vec![MINT_TO];
        data.extend_from_slice(&amount.to_le_bytes());
        let ix = Instruction {
            program_id: Self::token_program_id(),
            accounts: vec![
                AccountMeta::new(*mint, false),
                AccountMeta::new(*account, false),
                AccountMeta::new_readonly(self.payer.pubkey(), true),
            ],
            data,
        };
        self.send(&[ix], &[&self.payer.insecure_clone()])
    }

    /// The token-level balance of an SPL token account.
    pub fn token_balance(&self, account: &Pubkey) -> Option<u64> {
        let data = self.account_data(account)?;
        let bytes: [u8; 8] = data.get(64..72)?.try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    }

    /// Register `mint` with the pool: create its asset-registry PDA and
    /// token vault (spec: `create_spl_interface`). Signed by the protocol
    /// authority, which also pays the PDA rent. Returns (registry, vault).
    pub fn create_spl_interface(
        &mut self,
        authority: &Keypair,
        mint: &Pubkey,
    ) -> Result<(Pubkey, Pubkey), RigError> {
        let registry = self.spl_asset_registry_pda(mint);
        let vault = self.spl_asset_vault_pda(mint);
        let data = encode_instruction(tag::CREATE_SPL_INTERFACE, &CreateSplInterfaceData);
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new_readonly(self.protocol_config_pda(), false),
                AccountMeta::new(self.spl_asset_counter_pda(), false),
                AccountMeta::new(registry, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new(vault, false),
                AccountMeta::new_readonly(self.cpi_authority(), false),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new_readonly(Self::token_program_id(), false),
            ],
            data,
        };
        self.send(&[ix], &[&self.payer.insecure_clone(), authority])?;
        Ok((registry, vault))
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
        let accounts = vec![
            AccountMeta::new(tree.pubkey(), false),
            AccountMeta::new(depositor.pubkey(), true),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new(self.cpi_authority(), false),
            AccountMeta::new(depositor.pubkey(), false),
            AccountMeta::new_readonly(self.program_id, false),
        ];
        self.proofless_shield_with_accounts(accounts, depositor, data)
    }

    /// SPL `proofless_shield`: the depositor signs and pays from `user_token`,
    /// which they must own at the token level. Accounts: [tree, signer,
    /// cpi_authority, user_token, vault, registry, token_program,
    /// shielded_pool_program].
    pub fn proofless_shield_spl(
        &mut self,
        tree: &Keypair,
        depositor: &Keypair,
        user_token: &Pubkey,
        mint: &Pubkey,
        data: &ProoflessShieldIxData,
    ) -> Result<ProoflessShieldEvent, RigError> {
        let accounts = vec![
            AccountMeta::new(tree.pubkey(), false),
            AccountMeta::new(depositor.pubkey(), true),
            AccountMeta::new_readonly(self.cpi_authority(), false),
            AccountMeta::new(*user_token, false),
            AccountMeta::new(self.spl_asset_vault_pda(mint), false),
            AccountMeta::new_readonly(self.spl_asset_registry_pda(mint), false),
            AccountMeta::new_readonly(Self::token_program_id(), false),
            AccountMeta::new_readonly(self.program_id, false),
        ];
        self.proofless_shield_with_accounts(accounts, depositor, data)
    }

    /// `proofless_shield` with a caller-supplied account list, for tests that
    /// mutate the account shape.
    pub fn proofless_shield_with_accounts(
        &mut self,
        accounts: Vec<AccountMeta>,
        depositor: &Keypair,
        data: &ProoflessShieldIxData,
    ) -> Result<ProoflessShieldEvent, RigError> {
        let encoded = encode_instruction(tag::PROOFLESS_SHIELD, data);
        let ix = Instruction {
            program_id: self.program_id,
            accounts,
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

    /// The test-only zone program (programs/zone-test); litesvm loads it here.
    pub fn zone_test_program_id() -> Pubkey {
        Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID)
    }

    /// The zone program's `zone_auth` signer PDA and its bump.
    pub fn zone_auth_pda(&self) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"zone_auth"], &Self::zone_test_program_id())
    }

    /// Load `zone_test_program.so` into the rig.
    pub fn load_zone_test_program(&mut self) -> Result<(), RigError> {
        let path = default_zone_test_program_path();
        if !path.exists() {
            return Err(RigError::MissingProgram(path));
        }
        let bytes = std::fs::read(&path)?;
        self.svm
            .add_program(Self::zone_test_program_id(), &bytes)
            .map_err(|e| RigError::Litesvm(format!("add_zone_test: {e:?}")))?;
        Ok(())
    }

    /// A SOL `ZoneProoflessShieldIxData` whose `cpi_signer` names the zone test
    /// program and its `zone_auth` bump.
    pub fn zone_sol_shield_data(
        &self,
        lamports: u64,
        owner_utxo_hash: [u8; 32],
    ) -> ZoneProoflessShieldIxData {
        let (_, bump) = self.zone_auth_pda();
        ZoneProoflessShieldIxData {
            view_tag: [0u8; 32],
            owner_utxo_hash,
            salt: [0u8; 16],
            public_sol_amount: Some(lamports),
            public_spl_amount: None,
            cpi_signer: CpiSignerData {
                program_id: ZONE_TEST_PROGRAM_ID,
                bump,
            },
            policy_data_hash: None,
            zone_data: None,
            program_data_hash: None,
            program_data: None,
        }
    }

    /// Drive a `zone_proofless_shield` SOL deposit through the zone test
    /// program, which signs with its `zone_auth` PDA. Returns the emitted
    /// event (read from the inner `emit_event`, like a real indexer).
    /// `load_zone_test_program` must have been called first.
    pub fn zone_proofless_shield(
        &mut self,
        tree: &Keypair,
        depositor: &Keypair,
        data: &ZoneProoflessShieldIxData,
    ) -> Result<ProoflessShieldEvent, RigError> {
        let (zone_auth, _) = self.zone_auth_pda();
        // The zone test program forwards these to the shielded pool, with
        // zone_auth (account 2) signed via its invoke_signed seeds.
        let accounts = vec![
            AccountMeta::new(tree.pubkey(), false),
            AccountMeta::new(depositor.pubkey(), true),
            AccountMeta::new_readonly(zone_auth, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new(self.cpi_authority(), false),
            AccountMeta::new(depositor.pubkey(), false),
            AccountMeta::new_readonly(self.program_id, false),
        ];
        let ix = Instruction {
            program_id: Self::zone_test_program_id(),
            accounts,
            data: encode_instruction(tag::ZONE_PROOFLESS_SHIELD, data),
        };

        let payer = self.payer.pubkey();
        let message = Message::new(&[ix], Some(&payer));
        let account_keys = message.account_keys.clone();
        let blockhash = self.svm.latest_blockhash();
        let tx = Transaction::new(&[&self.payer.insecure_clone(), depositor], message, blockhash);
        let meta = self
            .svm
            .send_transaction(tx)
            .map_err(|e| RigError::Litesvm(format!("send_transaction: {e:?}")))?;

        // emit_event is a (nested) inner instruction invoked by the shielded
        // pool itself; iterate_flatten finds it regardless of CPI depth.
        for inner in meta.inner_instructions.iter().flatten() {
            let compiled = &inner.instruction;
            let program = account_keys
                .get(compiled.program_id_index as usize)
                .copied()
                .unwrap_or_default();
            if program == self.program_id && compiled.data.first() == Some(&tag::EMIT_EVENT) {
                return borsh::BorshDeserialize::try_from_slice(&compiled.data[1..])
                    .map_err(|e| RigError::Litesvm(format!("event decode: {e}")));
            }
        }
        Err(RigError::Litesvm("no emit_event inner instruction".into()))
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

/// Top-level system_program::CreateAccount (discriminator 0); the new
/// account co-signs.
fn system_create_account_ix(
    payer: &Pubkey,
    new_account: &Pubkey,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
) -> Instruction {
    let mut data = vec![0u8; 4 + 8 + 8 + 32];
    data[4..12].copy_from_slice(&lamports.to_le_bytes());
    data[12..20].copy_from_slice(&space.to_le_bytes());
    data[20..52].copy_from_slice(&owner.to_bytes());
    Instruction {
        program_id: Pubkey::default(),
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*new_account, true),
        ],
        data,
    }
}

/// litesvm loads the test-only zone program (programs/zone-test) at this id.
/// Any 32-byte value works; the program's `zone_auth` PDA derives from it.
pub const ZONE_TEST_PROGRAM_ID: [u8; 32] = *b"zone_test_program_aaaaaaaaaaaaaa";

/// Default location of `zone_test_program.so`: `<workspace>/target/deploy/`,
/// overridable via `ZONE_TEST_PROGRAM_PATH`.
fn default_zone_test_program_path() -> PathBuf {
    if let Ok(p) = std::env::var("ZONE_TEST_PROGRAM_PATH") {
        return PathBuf::from(p);
    }
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("..")
        .join("..")
        .join("target")
        .join("deploy")
        .join("zone_test_program.so")
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
