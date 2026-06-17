use borsh::BorshSerialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::{Pubkey, PubkeyError};

use crate::{
    instruction::{
        encode_instruction, tag, CreateZoneConfigData, UpdateZoneConfigData,
        UpdateZoneConfigOwnerData,
    },
    pda, SHIELDED_POOL_PROGRAM_ID,
};

pub fn create_zone_config(
    payer: Pubkey,
    data: CreateZoneConfigData,
) -> Result<Instruction, PubkeyError> {
    let zone_program = Pubkey::new_from_array(data.program_id.to_bytes());
    let zone_config = pda::zone_config_with_bump(&zone_program, data.zone_config_bump)?;
    let zone_auth = pda::zone_auth_with_bump(&zone_program, data.zone_auth_bump)?;

    Ok(Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(zone_config, false),
            AccountMeta::new_readonly(zone_auth, true),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ],
        data: encode_instruction(tag::CREATE_ZONE_CONFIG, &data),
    })
}

pub fn update_zone_config_owner(
    authority: Pubkey,
    zone_config: Pubkey,
    data: UpdateZoneConfigOwnerData,
) -> Instruction {
    let new_authority = Pubkey::new_from_array(data.new_authority.to_bytes());
    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(zone_config, false),
            AccountMeta::new_readonly(new_authority, true),
        ],
        data: encode_instruction(tag::UPDATE_ZONE_CONFIG_OWNER, &data),
    }
}

pub fn update_zone_config(
    authority: Pubkey,
    zone_config: Pubkey,
    data: UpdateZoneConfigData,
) -> Instruction {
    build_update_ix(tag::UPDATE_ZONE_CONFIG, authority, zone_config, data)
}

fn build_update_ix<T: BorshSerialize>(
    tag: u8,
    authority: Pubkey,
    zone_config: Pubkey,
    data: T,
) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(zone_config, false),
        ],
        data: encode_instruction(tag, &data),
    }
}
