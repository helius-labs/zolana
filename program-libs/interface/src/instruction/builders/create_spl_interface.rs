use borsh::BorshSerialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, CreateSplInterfaceData},
    SHIELDED_POOL_PROGRAM_ID,
};

pub fn create_spl_interface(
    authority: Pubkey,
    protocol_config: Pubkey,
    asset_counter: Pubkey,
    registry: Pubkey,
    mint: Pubkey,
    vault: Pubkey,
    cpi_authority: Pubkey,
    system_program: Pubkey,
    token_program: Pubkey,
    data: CreateSplInterfaceData,
) -> Instruction {
    let mut instruction_data = vec![tag::CREATE_SPL_INTERFACE];
    data.serialize(&mut instruction_data)
        .expect("shielded-pool instruction serialization is infallible");

    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(protocol_config, false),
            AccountMeta::new(asset_counter, false),
            AccountMeta::new(registry, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(cpi_authority, false),
            AccountMeta::new_readonly(system_program, false),
            AccountMeta::new_readonly(token_program, false),
        ],
        data: instruction_data,
    }
}
