use borsh::BorshSerialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, TransactData},
    SHIELDED_POOL_PROGRAM_ID,
};

pub fn transact(authority: Pubkey, tree: Pubkey, data: TransactData) -> Instruction {
    let mut instruction_data = vec![tag::TRANSACT];
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
