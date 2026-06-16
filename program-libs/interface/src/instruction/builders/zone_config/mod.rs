use borsh::BorshSerialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::{Pubkey, PubkeyError};

use crate::{
    instruction::{
        encode_instruction, tag, CreateZoneConfigData, UpdateZoneConfigData,
        UpdateZoneConfigOwnerData,
    },
    SHIELDED_POOL_PROGRAM_ID, SPP_ZONE_CONFIG_PDA_SEED, ZONE_AUTH_PDA_SEED,
};

pub fn create_zone_config(
    payer: Pubkey,
    data: CreateZoneConfigData,
) -> Result<Instruction, PubkeyError> {
    let zone_config = zone_config_pda(&data)?;
    let zone_auth = zone_auth_pda(&data)?;

    Ok(Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new(payer, true),
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

fn zone_config_pda(data: &CreateZoneConfigData) -> Result<Pubkey, PubkeyError> {
    let bump = [data.zone_config_bump];
    Pubkey::create_program_address(
        &[
            SPP_ZONE_CONFIG_PDA_SEED,
            data.program_id.as_ref(),
            bump.as_slice(),
        ],
        &Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
    )
}

fn zone_auth_pda(data: &CreateZoneConfigData) -> Result<Pubkey, PubkeyError> {
    let bump = [data.zone_auth_bump];
    Pubkey::create_program_address(
        &[ZONE_AUTH_PDA_SEED, bump.as_slice()],
        &Pubkey::new_from_array(data.program_id),
    )
}
