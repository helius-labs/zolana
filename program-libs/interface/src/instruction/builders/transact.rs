use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{encode_instruction, tag, TransactIxData},
    SHIELDED_POOL_PROGRAM_ID,
};

pub fn transact(authority: Pubkey, tree: Pubkey, data: TransactIxData) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(tree, false),
        ],
        data: encode_instruction(tag::TRANSACT, &data),
    }
}
