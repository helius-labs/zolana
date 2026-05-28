use borsh::BorshSerialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, CreatePoolTreeData},
    SHIELDED_POOL_PROGRAM_ID,
};

/// Initialize a combined-account shielded-pool tree (state sub-tree +
/// address sub-tree co-located).
pub fn create_pool_tree(payer: Pubkey, tree: Pubkey, data: CreatePoolTreeData) -> Instruction {
    let mut instruction_data = vec![tag::CREATE_POOL_TREE];
    data.serialize(&mut instruction_data)
        .expect("shielded-pool instruction serialization is infallible");

    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![AccountMeta::new(payer, true), AccountMeta::new(tree, false)],
        data: instruction_data,
    }
}
