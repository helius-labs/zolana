use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{
        encode_instruction, tag, CpiSignerData, CreateZoneConfigData, ProoflessShieldEvent,
        UpdateZoneConfigData, UpdateZoneConfigOwnerData, ZoneProoflessShieldIxData,
    },
    SPP_ZONE_CONFIG_PDA_SEED,
};
use zolana_keypair::constants::BLINDING_LEN;
use zolana_transaction::Wallet;

use crate::{
    instructions::{zone_auth_pda, zone_proofless_shield_sol_instruction, ZONE_TEST_PROGRAM_ID},
    paths::default_zone_test_program_path,
    single_proofless_shield_event,
    wallet_data::wallet_shield_fields,
    ProgramTestError, ZolanaProgramTest,
};

impl ZolanaProgramTest {
    pub fn zone_config_pda(&self, zone_program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[SPP_ZONE_CONFIG_PDA_SEED, zone_program_id.as_ref()],
            &self.program_id,
        )
    }

    fn zone_test_program_id() -> Pubkey {
        Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID)
    }

    pub fn zone_auth_pda(&self) -> (Pubkey, u8) {
        zone_auth_pda(&Self::zone_test_program_id())
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
        self.send(&[ix], &[payer])?;
        Ok(zone_config)
    }

    pub fn update_zone_config_owner(
        &mut self,
        authority: &Keypair,
        zone_config: &Pubkey,
        new_authority: &Pubkey,
    ) -> Result<(), ProgramTestError> {
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
        self.send(&[ix], &[authority])
    }

    pub fn update_zone_config(
        &mut self,
        authority: &Keypair,
        zone_config: &Pubkey,
        zone_authority_transact_is_enabled: bool,
    ) -> Result<(), ProgramTestError> {
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
        self.send(&[ix], &[authority])
    }

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
    ) -> Result<ZoneProoflessShieldIxData, ProgramTestError> {
        let (_, bump) = self.zone_auth_pda();
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
    ) -> Result<ZoneProoflessShieldIxData, ProgramTestError> {
        let fields = wallet_shield_fields(recipient, blinding_seed, position)?;
        Ok(ZoneProoflessShieldIxData {
            view_tag: fields.view_tag,
            owner_utxo_hash: fields.owner_utxo_hash,
            salt: fields.salt,
            public_sol_amount: Some(lamports),
            public_spl_amount: None,
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

    pub fn zone_proofless_shield(
        &mut self,
        tree: &Keypair,
        depositor: &Keypair,
        data: &ZoneProoflessShieldIxData,
    ) -> Result<ProoflessShieldEvent, ProgramTestError> {
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
        let outcome = self.create_and_send_default_payer_transaction(&[ix], &[depositor])?;
        single_proofless_shield_event(&outcome.events)
    }
}
