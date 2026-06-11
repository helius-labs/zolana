use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{encode_instruction, tag, BatchUpdateAddressTreeData},
    SHIELDED_POOL_PROGRAM_ID,
};

pub fn batch_update_address_tree(
    authority: Pubkey,
    tree: Pubkey,
    data: BatchUpdateAddressTreeData,
) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(tree, false),
        ],
        data: encode_instruction(tag::BATCH_UPDATE_ADDRESS_TREE, &data),
    }
}
