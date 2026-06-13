use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{encode_instruction, tag, BatchUpdateNullifierTreeData},
    SHIELDED_POOL_PROGRAM_ID,
};

pub fn batch_update_nullifier_tree(
    authority: Pubkey,
    protocol_config: Pubkey,
    tree: Pubkey,
    data: BatchUpdateNullifierTreeData,
) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(protocol_config, false),
            AccountMeta::new(tree, false),
        ],
        data: encode_instruction(tag::BATCH_UPDATE_NULLIFIER_TREE, &data),
    }
}
