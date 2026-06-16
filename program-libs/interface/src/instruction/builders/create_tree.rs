use borsh::BorshSerialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, CreateTreeData},
    pda, SHIELDED_POOL_PROGRAM_ID,
};

/// Initialize a combined-account shielded-pool tree (state sub-tree +
/// address sub-tree co-located). Tree creation is admin-gated: `authority` must
/// be the signer named by the canonical protocol config, otherwise anyone could
/// stand up a rogue tree and drain the shared vault against roots they control.
/// `owner` becomes the access-metadata owner of the tree.
pub fn create_tree(authority: Pubkey, tree: Pubkey, owner: Pubkey) -> Instruction {
    let mut data = vec![tag::CREATE_TREE];
    CreateTreeData {
        owner: owner.to_bytes(),
    }
    .serialize(&mut data)
    .expect("shielded-pool instruction serialization is infallible");

    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(tree, false),
        ],
        data,
    }
}
