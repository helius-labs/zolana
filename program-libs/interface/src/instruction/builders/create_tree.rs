use borsh::BorshSerialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, CreateTreeData},
    SHIELDED_POOL_PROGRAM_ID,
};

/// Initialize a combined-account shielded-pool tree (utxo sub-tree +
/// nullifier sub-tree co-located). Tree creation is admin-gated: `authority`
/// must be the signer named by the canonical `protocol_config`, otherwise anyone
/// could stand up a rogue tree and drain the shared vault against roots they
/// control. `owner` becomes the access-metadata owner of the nullifier tree.
pub fn create_tree(
    authority: Pubkey,
    protocol_config: Pubkey,
    tree: Pubkey,
    owner: Pubkey,
) -> Instruction {
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
            AccountMeta::new_readonly(protocol_config, false),
            AccountMeta::new(tree, false),
        ],
        data,
    }
}
