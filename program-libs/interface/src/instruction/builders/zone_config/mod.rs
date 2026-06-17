use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::{Pubkey, PubkeyError};

use crate::{
    instruction::{
        encode_instruction, tag, CreateZoneConfigData, UpdateZoneConfigData,
        UpdateZoneConfigOwnerData,
    },
    pda, PROGRAM_ID_PUBKEY,
};

pub struct CreateZoneConfig {
    pub payer: Pubkey,
    pub program_id: Address,
    pub zone_auth_bump: u8,
    pub authority: Address,
    pub zone_authority_transact_is_enabled: bool,
    pub zone_config_bump: u8,
}

impl CreateZoneConfig {
    pub fn instruction(&self) -> Result<Instruction, PubkeyError> {
        let data = CreateZoneConfigData {
            program_id: self.program_id,
            zone_auth_bump: self.zone_auth_bump,
            authority: self.authority,
            zone_authority_transact_is_enabled: self.zone_authority_transact_is_enabled,
            zone_config_bump: self.zone_config_bump,
        };

        let zone_program = Pubkey::new_from_array(data.program_id.to_bytes());
        let zone_config = pda::zone_config_with_bump(&zone_program, data.zone_config_bump)?;
        let zone_auth = pda::zone_auth_with_bump(&zone_program, data.zone_auth_bump)?;

        Ok(Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(pda::protocol_config(), false),
                AccountMeta::new(zone_config, false),
                AccountMeta::new_readonly(zone_auth, true),
                AccountMeta::new_readonly(Pubkey::default(), false),
            ],
            data: encode_instruction(tag::CREATE_ZONE_CONFIG, &data),
        })
    }
}

pub struct UpdateZoneConfigOwner {
    pub authority: Pubkey,
    pub zone_config: Pubkey,
    pub new_authority: Address,
}

impl UpdateZoneConfigOwner {
    pub fn instruction(&self) -> Instruction {
        let new_authority = Pubkey::new_from_array(self.new_authority.to_bytes());
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new(self.zone_config, false),
                AccountMeta::new_readonly(new_authority, true),
            ],
            data: encode_instruction(
                tag::UPDATE_ZONE_CONFIG_OWNER,
                &UpdateZoneConfigOwnerData {
                    new_authority: self.new_authority,
                },
            ),
        }
    }
}

pub struct UpdateZoneConfig {
    pub authority: Pubkey,
    pub zone_config: Pubkey,
    pub zone_authority_transact_is_enabled: bool,
}

impl UpdateZoneConfig {
    pub fn instruction(&self) -> Instruction {
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new(self.zone_config, false),
            ],
            data: encode_instruction(
                tag::UPDATE_ZONE_CONFIG,
                &UpdateZoneConfigData {
                    zone_authority_transact_is_enabled: self.zone_authority_transact_is_enabled,
                },
            ),
        }
    }
}
