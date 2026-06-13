use borsh::BorshSerialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{
        encode_instruction, tag, CreateZoneConfigData, UpdateZoneConfigData,
        UpdateZoneConfigOwnerData,
    },
    SHIELDED_POOL_PROGRAM_ID,
};

pub fn create_zone_config(
    payer: Pubkey,
    zone_config: Pubkey,
    zone_auth: Pubkey,
    data: CreateZoneConfigData,
) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(zone_config, false),
            AccountMeta::new_readonly(zone_auth, true),
        ],
        data: encode_instruction(tag::CREATE_ZONE_CONFIG, &data),
    }
}

pub fn update_zone_config_owner(
    authority: Pubkey,
    zone_config: Pubkey,
    data: UpdateZoneConfigOwnerData,
) -> Instruction {
    build_update_ix(tag::UPDATE_ZONE_CONFIG_OWNER, authority, zone_config, data)
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
