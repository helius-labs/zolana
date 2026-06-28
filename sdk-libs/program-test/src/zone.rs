use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{
        encode_instruction, tag, CreateZoneConfigData, DepositSplAccounts, UpdateZoneConfig,
        UpdateZoneConfigOwner, ZoneDeposit, ZoneDepositIxData,
    },
    pda,
};
use zolana_keypair::constants::BLINDING_LEN;
use zolana_transaction::Wallet;

use crate::{
    instructions::ZONE_TEST_PROGRAM_ID, paths::default_zone_test_program_path, single_deposit_view,
    wallet_data::wallet_shield_fields, DepositOutput, ProgramTestError, ZolanaProgramTest,
};

impl ZolanaProgramTest {
    fn zone_test_program_id() -> Pubkey {
        Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID)
    }

    pub fn load_zone_test_program(&mut self) -> Result<(), ProgramTestError> {
        let path = default_zone_test_program_path();
        if !path.exists() {
            return Err(ProgramTestError::MissingProgram(path));
        }
        let bytes = std::fs::read(&path)?;
        self.svm
            .add_program(Self::zone_test_program_id(), &bytes)
            .map_err(|e| ProgramTestError::Litesvm(format!("add_zone_test: {e:?}")))?;
        Ok(())
    }

    pub fn create_zone_config(
        &mut self,
        payer: &Keypair,
        authority: &Pubkey,
        zone_authority_transact_is_enabled: bool,
    ) -> Result<Pubkey, ProgramTestError> {
        let zone_program = Self::zone_test_program_id();
        // The config account IS the zone's canonical `zone_auth` PDA.
        let (zone_config, _) = pda::zone_auth(&zone_program);
        let data = CreateZoneConfigData {
            program_id: ZONE_TEST_PROGRAM_ID.into(),
            authority: authority.to_bytes().into(),
            zone_authority_transact_is_enabled,
        };
        let ix = Instruction {
            program_id: zone_program,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(pda::protocol_config(), false),
                AccountMeta::new(zone_config, false),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new_readonly(self.program_id, false),
            ],
            data: encode_instruction(tag::CREATE_ZONE_CONFIG, &data),
        };
        self.send(&[ix], &[payer])?;
        Ok(zone_config)
    }

    pub fn update_zone_config_owner(
        &mut self,
        authority: &Keypair,
        zone_config: &Pubkey,
        new_authority: &Keypair,
    ) -> Result<(), ProgramTestError> {
        let ix = UpdateZoneConfigOwner {
            authority: authority.pubkey(),
            zone_config: *zone_config,
            new_authority: new_authority.pubkey().to_bytes().into(),
        }
        .instruction();
        let mut signers = vec![authority];
        if new_authority.pubkey() != authority.pubkey() {
            signers.push(new_authority);
        }
        self.send(&[ix], &signers)
    }

    pub fn update_zone_config(
        &mut self,
        authority: &Keypair,
        zone_config: &Pubkey,
        zone_authority_transact_is_enabled: bool,
    ) -> Result<(), ProgramTestError> {
        let ix = UpdateZoneConfig {
            authority: authority.pubkey(),
            zone_config: *zone_config,
            zone_authority_transact_is_enabled,
        }
        .instruction();
        self.send(&[ix], &[authority])
    }

    pub fn zone_sol_shield_data(
        &self,
        lamports: u64,
        owner: [u8; 32],
        blinding: [u8; BLINDING_LEN],
    ) -> ZoneDepositIxData {
        ZoneDepositIxData {
            view_tag: [0u8; 32],
            owner,
            blinding,
            public_amount: Some(lamports),
            zone_data_hash: [0u8; 32],
            zone_data: Vec::new(),
            program: None,
        }
    }

    pub fn wallet_zone_sol_shield_data(
        &self,
        lamports: u64,
        recipient: &Wallet,
        blinding_seed: &[u8; BLINDING_LEN],
        position: u8,
    ) -> Result<ZoneDepositIxData, ProgramTestError> {
        let fields = wallet_shield_fields(recipient, blinding_seed, position)?;
        Ok(ZoneDepositIxData {
            view_tag: fields.view_tag,
            owner: fields.owner,
            blinding: fields.blinding,
            public_amount: Some(lamports),
            zone_data_hash: [0u8; 32],
            zone_data: Vec::new(),
            program: None,
        })
    }

    pub fn wallet_zone_spl_shield_data(
        &self,
        amount: u64,
        recipient: &Wallet,
        blinding_seed: &[u8; BLINDING_LEN],
        position: u8,
    ) -> Result<ZoneDepositIxData, ProgramTestError> {
        let fields = wallet_shield_fields(recipient, blinding_seed, position)?;
        Ok(ZoneDepositIxData {
            view_tag: fields.view_tag,
            owner: fields.owner,
            blinding: fields.blinding,
            public_amount: Some(amount),
            zone_data_hash: [0u8; 32],
            zone_data: Vec::new(),
            program: None,
        })
    }

    pub fn zone_deposit(
        &mut self,
        tree: &Pubkey,
        depositor: &Keypair,
        data: &ZoneDepositIxData,
    ) -> Result<DepositOutput, ProgramTestError> {
        let ix = ZoneDeposit {
            tree: *tree,
            depositor: depositor.pubkey(),
            spl: None,
            view_tag: data.view_tag,
            owner: data.owner,
            blinding: data.blinding,
            public_amount: data.public_amount,
            zone_program_id: Self::zone_test_program_id(),
            zone_data_hash: data.zone_data_hash,
            zone_data: data.zone_data.clone(),
            program: data.program.clone(),
        }
        .instruction()
        .map_err(|err| ProgramTestError::Rpc(format!("zone auth PDA: {err}")))?;
        let outcome = self.create_and_send_default_payer_transaction(&[ix], &[depositor])?;
        single_deposit_view(&outcome.events)
    }

    pub fn zone_deposit_spl(
        &mut self,
        tree: &Pubkey,
        depositor: &Keypair,
        user_token: &Pubkey,
        mint: &Pubkey,
        data: &ZoneDepositIxData,
    ) -> Result<DepositOutput, ProgramTestError> {
        let ix = ZoneDeposit {
            tree: *tree,
            depositor: depositor.pubkey(),
            spl: Some(DepositSplAccounts {
                user_token: *user_token,
                vault: pda::spl_asset_vault(mint),
                registry: pda::spl_asset_registry(mint),
                token_program: Self::token_program_id(),
            }),
            view_tag: data.view_tag,
            owner: data.owner,
            blinding: data.blinding,
            public_amount: data.public_amount,
            zone_program_id: Self::zone_test_program_id(),
            zone_data_hash: data.zone_data_hash,
            zone_data: data.zone_data.clone(),
            program: data.program.clone(),
        }
        .instruction()
        .map_err(|err| ProgramTestError::Rpc(format!("zone auth PDA: {err}")))?;
        let outcome = self.create_and_send_default_payer_transaction(&[ix], &[depositor])?;
        single_deposit_view(&outcome.events)
    }
}
