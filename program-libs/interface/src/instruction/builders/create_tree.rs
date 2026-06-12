use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{encode_instruction, tag, CreateTreeData},
    SHIELDED_POOL_PROGRAM_ID,
};

/// Initialize a combined-account shielded-pool tree (state sub-tree +
/// address sub-tree co-located). Tree creation is admin-gated: `authority` must
/// be the signer named by the canonical `protocol_config`, otherwise anyone
/// could stand up a rogue tree and drain the shared vault against roots they
/// control.
pub fn create_tree(
    authority: Pubkey,
    protocol_config: Pubkey,
    tree: Pubkey,
    data: CreateTreeData,
) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(protocol_config, false),
            AccountMeta::new(tree, false),
        ],
        data: encode_instruction(tag::CREATE_TREE, &data),
    }
}
