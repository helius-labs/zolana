use borsh::BorshSerialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, CreateAddressTreeData},
    SHIELDED_POOL_PROGRAM_ID,
};

pub fn create_address_tree(
    payer: Pubkey,
    tree: Pubkey,
    queue: Pubkey,
    data: CreateAddressTreeData,
) -> Instruction {
    let mut instruction_data = vec![tag::CREATE_ADDRESS_TREE];
    data.serialize(&mut instruction_data)
        .expect("shielded-pool instruction serialization is infallible");

    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new(queue, false),
        ],
        data: instruction_data,
    }
}
