use borsh::BorshSerialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, AppendStateLeavesData},
    SHIELDED_POOL_PROGRAM_ID,
};

pub fn append_state_leaves(
    authority: Pubkey,
    tree: Pubkey,
    data: AppendStateLeavesData,
) -> Instruction {
    let mut instruction_data = vec![tag::APPEND_STATE_LEAVES];
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
