use borsh::BorshSerialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, InsertAddressesData},
    SHIELDED_POOL_PROGRAM_ID,
};

pub fn insert_addresses(authority: Pubkey, tree: Pubkey, data: InsertAddressesData) -> Instruction {
    let mut instruction_data = vec![tag::INSERT_ADDRESSES];
    data.serialize(&mut instruction_data)
        .expect("shielded-pool instruction serialization is infallible");

    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(tree, false),
        ],
        data: instruction_data,
    }
}
