use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{instruction::tag, SHIELDED_POOL_PROGRAM_ID};

/// Initialize a combined-account shielded-pool tree (state sub-tree +
/// address sub-tree co-located). Tree creation is admin-gated: `authority` must
/// be the signer named by the canonical `protocol_config`, otherwise anyone
/// could stand up a rogue tree and drain the shared vault against roots they
/// control. The instruction carries no data beyond its tag byte.
pub fn create_tree(authority: Pubkey, protocol_config: Pubkey, tree: Pubkey) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(protocol_config, false),
            AccountMeta::new(tree, false),
        ],
        data: vec![tag::CREATE_TREE],
    }
}
