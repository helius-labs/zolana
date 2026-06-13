//! Litesvm-based test rig for the shielded-pool program.
//!
//! Boots a litesvm instance, loads the shielded-pool program (.so), and
//! exposes one-call helpers for every shielded-pool instruction plus state
//! accessors used by integration tests.
//!
//! Usage:
//! ```ignore
//! use zolana_program_test::PoolTestRig;
//!
//! let mut rig = PoolTestRig::new()?;
//! let tree = rig.create_tree()?;
//! let root = rig.state_root(&tree.pubkey())?;
//! ```

use std::path::{Path, PathBuf};

use borsh::BorshSerialize;
use litesvm::{types::TransactionMetadata, LiteSVM};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use thiserror::Error;
use zolana_interface::{
    instruction::{
        encode_instruction, tag, CpiSignerData, CreateProtocolConfigData, CreateSplInterfaceData,
        CreateTreeData, CreateZoneConfigData, PauseTreeData, ProoflessShieldEvent,
        ProoflessShieldIxData, UpdateProtocolConfigData, UpdateZoneConfigData,
        UpdateZoneConfigOwnerData, ZoneProoflessShieldIxData,
    },
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID, SPL_ASSET_COUNTER_PDA_SEED,
    SPL_ASSET_REGISTRY_PDA_SEED, SPL_ASSET_VAULT_PDA_SEED, SPL_TOKEN_PROGRAM_ID,
    SPP_PROTOCOL_CONFIG_PDA_SEED, SPP_ZONE_CONFIG_PDA_SEED, ZONE_AUTH_PDA_SEED,
};
use zolana_keypair::constants::BLINDING_LEN;
use zolana_transaction::{
    derive_blinding, Address, Blinding, Data, DataRecord, ProoflessDepositEvent, Wallet,
};

pub mod indexer;
pub use indexer::{PoolIndexer, UtxoRecord};

pub fn proofless_event_for_wallet(event: &ProoflessShieldEvent) -> ProoflessDepositEvent {
    let mut records = Vec::new();
    if let Some(zone_data) = event.zone_data.clone() {
        records.push(DataRecord::ZoneData(zone_data));
    }
    if let Some(program_data) = event.program_data.clone() {
        records.push(DataRecord::ProgramData(program_data));
    }
    ProoflessDepositEvent {
        view_tag: event.view_tag,
        utxo_hash: event.utxo_hash,
        owner_utxo_hash: event.owner_utxo_hash,
        asset: Address::new_from_array(event.asset),
        amount: event.amount,
        zone_program_id: event.zone_program_id.map(Address::new_from_array),
        program_data_hash: event.program_data_hash.unwrap_or([0u8; 32]),
        zone_data_hash: event.policy_data_hash.unwrap_or([0u8; 32]),
        data: Data::new(records),
    }
}

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
        Pubkey::find_program_address(&[SPL_ASSET_VAULT_PDA_SEED, mint.as_ref()], &self.program_id).0
    }

    pub fn zone_config_pda(&self, zone_program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[SPP_ZONE_CONFIG_PDA_SEED, zone_program_id.as_ref()],
            &self.program_id,
        )
    }

    /// Create the canonical protocol config naming `authority`. The authority
    /// signs and pays the PDA rent, so it is funded here.
    pub fn create_protocol_config(&mut self, authority: &Keypair) -> Result<Pubkey, RigError> {
        self.create_protocol_config_with_merge_authorities(authority, Vec::new())
    }

    pub fn create_protocol_config_with_merge_authorities(
        &mut self,
        authority: &Keypair,
        merge_authorities: Vec<[u8; 32]>,
    ) -> Result<Pubkey, RigError> {
        self.airdrop(&authority.pubkey(), 1_000_000_000)?;
        let config = self.protocol_config_pda();
        let data = encode_instruction(
            tag::CREATE_PROTOCOL_CONFIG,
            &CreateProtocolConfigData {
                authority: authority.pubkey().to_bytes(),
                merge_authorities,
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
        self.update_protocol_config_with_merge_authorities(authority, new_authority, Vec::new())
    }

    pub fn update_protocol_config_with_merge_authorities(
        &mut self,
        authority: &Keypair,
        new_authority: &Pubkey,
        merge_authorities: Vec<[u8; 32]>,
    ) -> Result<(), RigError> {
        let data = encode_instruction(
            tag::UPDATE_PROTOCOL_CONFIG,
            &UpdateProtocolConfigData {
                authority: new_authority.to_bytes(),
                merge_authorities,
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

    /// Low-level SOL deposit data for error-path tests. Happy paths should
    /// use `wallet_sol_shield_data`.
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

    /// Low-level SPL deposit data for error-path tests. Happy paths should
    /// use `wallet_spl_shield_data`.
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

    pub fn wallet_sol_shield_data(
        lamports: u64,
        recipient: &Wallet,
        blinding_seed: &[u8; BLINDING_LEN],
        position: u8,
    ) -> Result<(ProoflessShieldIxData, Blinding), RigError> {
        let fields = wallet_shield_fields(recipient, blinding_seed, position)?;
        Ok((
            ProoflessShieldIxData {
                view_tag: fields.view_tag,
                owner_utxo_hash: fields.owner_utxo_hash,
                salt: fields.salt,
                public_sol_amount: Some(lamports),
                public_spl_amount: None,
                program_data_hash: None,
                program_data: None,
                cpi_signer: None,
            },
            fields.blinding,
        ))
    }

    pub fn wallet_spl_shield_data(
        amount: u64,
        recipient: &Wallet,
        blinding_seed: &[u8; BLINDING_LEN],
        position: u8,
    ) -> Result<(ProoflessShieldIxData, Blinding), RigError> {
        let fields = wallet_shield_fields(recipient, blinding_seed, position)?;
        Ok((
            ProoflessShieldIxData {
                view_tag: fields.view_tag,
                owner_utxo_hash: fields.owner_utxo_hash,
                salt: fields.salt,
                public_sol_amount: None,
                public_spl_amount: Some(amount),
                program_data_hash: None,
                program_data: None,
                cpi_signer: None,
            },
            fields.blinding,
        ))
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
        self.send(
            &[create_ix, init_ix],
            &[&self.payer.insecure_clone(), &mint],
        )?;
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
        let ix = proofless_shield_sol_instruction(
            self.program_id,
            tree.pubkey(),
            depositor.pubkey(),
            self.cpi_authority(),
            data,
        );
        self.send_proofless_shield_ix(ix, depositor)
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
        self.send_proofless_shield_ix(ix, depositor)
    }

    fn send_proofless_shield_ix(
        &mut self,
        ix: Instruction,
        depositor: &Keypair,
    ) -> Result<ProoflessShieldEvent, RigError> {
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

        self.proofless_event_from_meta(&account_keys, &meta)
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

    /// The test-only zone wrapper program; litesvm loads it here.
    fn zone_test_program_id() -> Pubkey {
        Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID)
    }

    /// The zone program's `zone_auth` signer PDA and its bump.
    pub fn zone_auth_pda(&self) -> (Pubkey, u8) {
        zone_auth_pda(&Self::zone_test_program_id())
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

    pub fn create_zone_config(
        &mut self,
        payer: &Keypair,
        authority: &Pubkey,
        zone_authority_transact_is_enabled: bool,
    ) -> Result<Pubkey, RigError> {
        let zone_program = Self::zone_test_program_id();
        let (zone_config, zone_config_bump) = self.zone_config_pda(&zone_program);
        let (zone_auth, zone_auth_bump) = self.zone_auth_pda();
        let data = CreateZoneConfigData {
            policy_program_id: ZONE_TEST_PROGRAM_ID,
            zone_auth_bump,
            authority: authority.to_bytes(),
            zone_authority_transact_is_enabled,
            zone_config_bump,
        };
        let ix = Instruction {
            program_id: zone_program,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(zone_config, false),
                AccountMeta::new_readonly(zone_auth, false),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new_readonly(self.program_id, false),
            ],
            data: encode_instruction(tag::CREATE_ZONE_CONFIG, &data),
        };
        self.send(&[ix], &[&self.payer.insecure_clone(), payer])?;
        Ok(zone_config)
    }

    pub fn update_zone_config_owner(
        &mut self,
        authority: &Keypair,
        zone_config: &Pubkey,
        new_authority: &Pubkey,
    ) -> Result<(), RigError> {
        let data = UpdateZoneConfigOwnerData {
            new_authority: new_authority.to_bytes(),
        };
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new(*zone_config, false),
            ],
            data: encode_instruction(tag::UPDATE_ZONE_CONFIG_OWNER, &data),
        };
        self.send(&[ix], &[&self.payer.insecure_clone(), authority])
    }

    pub fn update_zone_config(
        &mut self,
        authority: &Keypair,
        zone_config: &Pubkey,
        zone_authority_transact_is_enabled: bool,
    ) -> Result<(), RigError> {
        let data = UpdateZoneConfigData {
            zone_authority_transact_is_enabled,
        };
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new(*zone_config, false),
            ],
            data: encode_instruction(tag::UPDATE_ZONE_CONFIG, &data),
        };
        self.send(&[ix], &[&self.payer.insecure_clone(), authority])
    }

    /// SOL zone deposit data whose `cpi_signer` names the wrapper program and
    /// its `zone_auth` bump.
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

    pub fn wallet_zone_sol_shield_data(
        &self,
        lamports: u64,
        recipient: &Wallet,
        blinding_seed: &[u8; BLINDING_LEN],
        position: u8,
    ) -> Result<(ZoneProoflessShieldIxData, Blinding), RigError> {
        let (_, bump) = self.zone_auth_pda();
        let fields = wallet_shield_fields(recipient, blinding_seed, position)?;
        Ok((
            ZoneProoflessShieldIxData {
                view_tag: fields.view_tag,
                owner_utxo_hash: fields.owner_utxo_hash,
                salt: fields.salt,
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
            },
            fields.blinding,
        ))
    }

    /// Drive a `zone_proofless_shield` SOL deposit through the zone wrapper
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
        let ix = zone_proofless_shield_sol_instruction(
            self.program_id,
            Self::zone_test_program_id(),
            tree.pubkey(),
            depositor.pubkey(),
            zone_auth,
            self.cpi_authority(),
            data,
        );

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

        self.proofless_event_from_meta(&account_keys, &meta)
    }

    fn proofless_event_from_meta(
        &self,
        account_keys: &[Pubkey],
        meta: &TransactionMetadata,
    ) -> Result<ProoflessShieldEvent, RigError> {
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

    /// The on-chain state sub-tree root of a pool tree account.
    pub fn state_root(&self, tree: &Pubkey) -> Option<[u8; 32]> {
        let data = self.account_data(tree)?;
        let offset = shielded_pool_program::instructions::create_tree::init::state_root_offset();
        let slice = data.get(offset..offset + 32)?;
        let mut root = [0u8; 32];
        root.copy_from_slice(slice);
        Some(root)
    }

    /// Read the raw bytes of any account in the rig.
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

struct WalletShieldFields {
    view_tag: [u8; 32],
    owner_utxo_hash: [u8; 32],
    salt: [u8; 16],
    blinding: Blinding,
}

fn wallet_shield_fields(
    recipient: &Wallet,
    blinding_seed: &[u8; BLINDING_LEN],
    position: u8,
) -> Result<WalletShieldFields, RigError> {
    let blinding = derive_blinding(blinding_seed, position);
    let owner_utxo_hash = recipient.proofless_owner_utxo_hash(&blinding)?;
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&blinding_seed[..16]);
    salt[15] ^= position;
    Ok(WalletShieldFields {
        view_tag: recipient.keypair.recipient_bootstrap_view_tag(),
        owner_utxo_hash,
        salt,
        blinding,
    })
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

/// litesvm loads the test-only zone wrapper program at this id.
/// Any 32-byte value works; the program's `zone_auth` PDA derives from it.
pub const ZONE_TEST_PROGRAM_ID: [u8; 32] = *b"zone_test_program_aaaaaaaaaaaaaa";

pub fn zone_auth_pda(zone_program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[ZONE_AUTH_PDA_SEED], zone_program_id)
}

pub fn proofless_shield_sol_instruction(
    program_id: Pubkey,
    tree: Pubkey,
    depositor: Pubkey,
    cpi_authority: Pubkey,
    data: &ProoflessShieldIxData,
) -> Instruction {
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(tree, false),
            AccountMeta::new(depositor, true),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new(cpi_authority, false),
            AccountMeta::new(depositor, false),
            AccountMeta::new_readonly(program_id, false),
        ],
        data: encode_instruction(tag::PROOFLESS_SHIELD, data),
    }
}

pub fn zone_proofless_shield_sol_instruction(
    shielded_pool_program_id: Pubkey,
    zone_program_id: Pubkey,
    tree: Pubkey,
    depositor: Pubkey,
    zone_auth: Pubkey,
    cpi_authority: Pubkey,
    data: &ZoneProoflessShieldIxData,
) -> Instruction {
    Instruction {
        program_id: zone_program_id,
        accounts: vec![
            AccountMeta::new(tree, false),
            AccountMeta::new(depositor, true),
            AccountMeta::new_readonly(zone_auth, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new(cpi_authority, false),
            AccountMeta::new(depositor, false),
            AccountMeta::new_readonly(shielded_pool_program_id, false),
        ],
        data: encode_instruction(tag::ZONE_PROOFLESS_SHIELD, data),
    }
}

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
    // CARGO_MANIFEST_DIR points at program-tests/program-test at build time; the
    // workspace root is two levels up.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("..")
        .join("..")
        .join("target")
        .join("deploy")
        .join("shielded_pool_program.so")
}
