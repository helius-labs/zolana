use borsh::BorshSerialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{
        tag, CreatePocketConfigData, UpdatePocketConfigData, UpdatePocketConfigOwnerData,
    },
    SHIELDED_POOL_PROGRAM_ID,
};

pub fn create_pocket_config(
    payer: Pubkey,
    pocket_config: Pubkey,
    pocket_auth: Pubkey,
    data: CreatePocketConfigData,
) -> Instruction {
    let mut instruction_data = vec![tag::CREATE_POCKET_CONFIG];
    data.serialize(&mut instruction_data)
        .expect("shielded-pool instruction serialization is infallible");

    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new(pocket_config, false),
            AccountMeta::new_readonly(pocket_auth, true),
        ],
        data: instruction_data,
    }
}

pub fn update_pocket_config_owner(
    authority: Pubkey,
    pocket_config: Pubkey,
    data: UpdatePocketConfigOwnerData,
) -> Instruction {
    build_update_ix(
        tag::UPDATE_POCKET_CONFIG_OWNER,
        authority,
        pocket_config,
        data,
    )
}

pub fn update_pocket_config(
    authority: Pubkey,
    pocket_config: Pubkey,
    data: UpdatePocketConfigData,
) -> Instruction {
    build_update_ix(tag::UPDATE_POCKET_CONFIG, authority, pocket_config, data)
}

fn build_update_ix<T: BorshSerialize>(
    tag: u8,
    authority: Pubkey,
    pocket_config: Pubkey,
    data: T,
) -> Instruction {
    let mut instruction_data = vec![tag];
    data.serialize(&mut instruction_data)
        .expect("shielded-pool instruction serialization is infallible");

    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(pocket_config, false),
        ],
        data: instruction_data,
    }
}
