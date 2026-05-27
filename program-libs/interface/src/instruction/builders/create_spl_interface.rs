use borsh::BorshSerialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, CreateSplInterfaceData},
    SHIELDED_POOL_PROGRAM_ID,
};

pub fn create_spl_interface(
    payer: Pubkey,
    registry: Pubkey,
    mint: Pubkey,
    data: CreateSplInterfaceData,
) -> Instruction {
    let mut instruction_data = vec![tag::CREATE_SPL_INTERFACE];
    data.serialize(&mut instruction_data)
        .expect("shielded-pool instruction serialization is infallible");

    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(registry, false),
            AccountMeta::new_readonly(mint, false),
        ],
        data: instruction_data,
    }
}
