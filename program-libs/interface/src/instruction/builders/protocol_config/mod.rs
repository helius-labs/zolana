use borsh::BorshSerialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{
        encode_instruction, tag, CreateProtocolConfigData, PauseTreeData, UpdateProtocolConfigData,
    },
    SHIELDED_POOL_PROGRAM_ID,
};

use super::protocol_config_pda;

/// Initialize the canonical protocol-config PDA. The program creates the PDA via
/// CPI, so the authority is the rent payer (writable signer) and the system
/// program must be present.
pub fn create_protocol_config(authority: Pubkey, data: CreateProtocolConfigData) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(protocol_config_pda(), false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ],
        data: encode_instruction(tag::CREATE_PROTOCOL_CONFIG, &data),
    }
}

pub fn update_protocol_config(authority: Pubkey, data: UpdateProtocolConfigData) -> Instruction {
    build_config_ix(tag::UPDATE_PROTOCOL_CONFIG, authority, None, data)
}

pub fn pause_tree(authority: Pubkey, tree: Pubkey, data: PauseTreeData) -> Instruction {
    build_config_ix(tag::PAUSE_TREE, authority, Some(tree), data)
}

fn build_config_ix<T: BorshSerialize>(
    tag: u8,
    authority: Pubkey,
    tree: Option<Pubkey>,
    data: T,
) -> Instruction {
    let mut accounts = vec![
        AccountMeta::new_readonly(authority, true),
        AccountMeta::new(protocol_config_pda(), false),
    ];
    if let Some(tree) = tree {
        accounts.push(AccountMeta::new(tree, false));
    }

    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts,
        data: encode_instruction(tag, &data),
    }
}
