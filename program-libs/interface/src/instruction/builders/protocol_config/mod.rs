use borsh::BorshSerialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{
        encode_instruction, tag, CreateProtocolConfigData, PauseTreeData, UpdateProtocolConfigData,
    },
    SHIELDED_POOL_PROGRAM_ID,
};

/// Initialize the canonical protocol-config PDA. The program creates the PDA via
/// CPI, so the authority is the rent payer (writable signer) and the system
/// program must be present. `protocol_config` must be the
/// `[SPP_PROTOCOL_CONFIG_PDA_SEED]` PDA or the program rejects it.
pub fn create_protocol_config(
    authority: Pubkey,
    protocol_config: Pubkey,
    data: CreateProtocolConfigData,
) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(protocol_config, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ],
        data: encode_instruction(tag::CREATE_PROTOCOL_CONFIG, &data),
    }
}

pub fn update_protocol_config(
    authority: Pubkey,
    protocol_config: Pubkey,
    data: UpdateProtocolConfigData,
) -> Instruction {
    build_config_ix(
        tag::UPDATE_PROTOCOL_CONFIG,
        authority,
        protocol_config,
        None,
        data,
    )
}

pub fn pause_tree(
    authority: Pubkey,
    protocol_config: Pubkey,
    tree: Pubkey,
    data: PauseTreeData,
) -> Instruction {
    build_config_ix(
        tag::PAUSE_TREE,
        authority,
        protocol_config,
        Some(tree),
        data,
    )
}

fn build_config_ix<T: BorshSerialize>(
    tag: u8,
    authority: Pubkey,
    protocol_config: Pubkey,
    tree: Option<Pubkey>,
    data: T,
) -> Instruction {
    let mut accounts = vec![
        AccountMeta::new_readonly(authority, true),
        AccountMeta::new(protocol_config, false),
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
