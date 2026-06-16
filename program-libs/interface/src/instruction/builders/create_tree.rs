use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{instruction::tag, SHIELDED_POOL_PROGRAM_ID};

use super::protocol_config_pda;

/// Initialize a combined-account shielded-pool tree (state sub-tree +
/// address sub-tree co-located). Tree creation is admin-gated: `authority` must
/// be the signer named by the canonical protocol config. The instruction
/// carries no data beyond its tag byte.
pub fn create_tree(authority: Pubkey, tree: Pubkey) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(protocol_config_pda(), false),
            AccountMeta::new(tree, false),
        ],
        data: vec![tag::CREATE_TREE],
    }
}
