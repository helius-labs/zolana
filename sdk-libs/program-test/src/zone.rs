use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    event::DepositView,
    instruction::{
        encode_instruction, tag, update_zone_config as update_zone_config_ix,
        update_zone_config_owner as update_zone_config_owner_ix, CpiSignerData,
        CreateZoneConfigData, DepositSplAccounts, UpdateZoneConfigData, UpdateZoneConfigOwnerData,
        ZoneDepositAccounts, ZoneDepositIxData,
    },
    pda,
};
use zolana_keypair::constants::BLINDING_LEN;
use zolana_transaction::Wallet;

use crate::{
    instructions::ZONE_TEST_PROGRAM_ID, paths::default_zone_test_program_path, single_deposit_view,
    wallet_data::wallet_shield_fields, ProgramTestError, ZolanaProgramTest,
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
        let (zone_config, zone_config_bump) = pda::zone_config(&zone_program);
        let (zone_auth, zone_auth_bump) = pda::zone_auth(&zone_program);
        let data = CreateZoneConfigData {
            program_id: ZONE_TEST_PROGRAM_ID.into(),
            zone_auth_bump,
            authority: authority.to_bytes().into(),
            zone_authority_transact_is_enabled,
            zone_config_bump,
        };
        let ix = Instruction {
            program_id: zone_program,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(pda::protocol_config(), false),
                AccountMeta::new(zone_config, false),
                AccountMeta::new_readonly(zone_auth, false),
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
        new_authority: &Pubkey,
    ) -> Result<(), ProgramTestError> {
        let ix = update_zone_config_owner_ix(
            authority.pubkey(),
            *zone_config,
            UpdateZoneConfigOwnerData {
                new_authority: new_authority.to_bytes().into(),
            },
        );
        self.send(&[ix], &[authority])
    }

    pub fn update_zone_config(
        &mut self,
        authority: &Keypair,
        zone_config: &Pubkey,
        zone_authority_transact_is_enabled: bool,
    ) -> Result<(), ProgramTestError> {
        let ix = update_zone_config_ix(
            authority.pubkey(),
            *zone_config,
            UpdateZoneConfigData {
                zone_authority_transact_is_enabled,
            },
        );
        self.send(&[ix], &[authority])
    }

    pub fn zone_sol_shield_data(
        &self,
        lamports: u64,
        owner_utxo_hash: [u8; 32],
    ) -> ZoneDepositIxData {
        let (_, bump) = pda::zone_auth(&Self::zone_test_program_id());
        ZoneDepositIxData {
            view_tag: [0u8; 32],
            owner_utxo_hash,
            salt: [0u8; 16],
            public_amount: Some(lamports),
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
    ) -> Result<ZoneDepositIxData, ProgramTestError> {
        let (_, bump) = pda::zone_auth(&Self::zone_test_program_id());
        Self::wallet_zone_sol_shield_data_for_zone(
            lamports,
            recipient,
            blinding_seed,
            position,
            ZONE_TEST_PROGRAM_ID,
            bump,
        )
    }

    pub fn wallet_zone_sol_shield_data_for_zone(
        lamports: u64,
        recipient: &Wallet,
        blinding_seed: &[u8; BLINDING_LEN],
        position: u8,
        zone_program_id: [u8; 32],
        zone_auth_bump: u8,
    ) -> Result<ZoneDepositIxData, ProgramTestError> {
        let fields = wallet_shield_fields(recipient, blinding_seed, position)?;
        Ok(ZoneDepositIxData {
            view_tag: fields.view_tag,
            owner_utxo_hash: fields.owner_utxo_hash,
            salt: fields.salt,
            public_amount: Some(lamports),
            cpi_signer: CpiSignerData {
                program_id: zone_program_id,
                bump: zone_auth_bump,
            },
            policy_data_hash: None,
            zone_data: None,
            program_data_hash: None,
            program_data: None,
        })
    }

    pub fn wallet_zone_spl_shield_data(
        &self,
        amount: u64,
        recipient: &Wallet,
        blinding_seed: &[u8; BLINDING_LEN],
        position: u8,
    ) -> Result<ZoneDepositIxData, ProgramTestError> {
        let (_, bump) = pda::zone_auth(&Self::zone_test_program_id());
        let fields = wallet_shield_fields(recipient, blinding_seed, position)?;
        Ok(ZoneDepositIxData {
            view_tag: fields.view_tag,
            owner_utxo_hash: fields.owner_utxo_hash,
            salt: fields.salt,
            public_amount: Some(amount),
            cpi_signer: CpiSignerData {
                program_id: ZONE_TEST_PROGRAM_ID,
                bump,
            },
            policy_data_hash: None,
            zone_data: None,
            program_data_hash: None,
            program_data: None,
        })
    }

    pub fn zone_deposit(
        &mut self,
        tree: &Pubkey,
        depositor: &Keypair,
        data: &ZoneDepositIxData,
    ) -> Result<DepositView, ProgramTestError> {
        let ix = data
            .instruction(ZoneDepositAccounts::sol(*tree, depositor.pubkey()))
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
    ) -> Result<DepositView, ProgramTestError> {
        let ix = data
            .instruction(ZoneDepositAccounts::spl(
                *tree,
                depositor.pubkey(),
                DepositSplAccounts {
                    user_token: *user_token,
                    vault: pda::spl_asset_vault(mint),
                    registry: pda::spl_asset_registry(mint),
                    token_program: Self::token_program_id(),
                },
            ))
            .map_err(|err| ProgramTestError::Rpc(format!("zone auth PDA: {err}")))?;
        let outcome = self.create_and_send_default_payer_transaction(&[ix], &[depositor])?;
        single_deposit_view(&outcome.events)
    }
}
