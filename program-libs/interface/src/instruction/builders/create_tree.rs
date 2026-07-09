use borsh::BorshSerialize;
use rings_batched_merkle_tree::initialize_address_tree::InitAddressTreeAccountsInstructionData;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, CreateTreeData},
    pda, PROGRAM_ID_PUBKEY,
};

/// Initialize a combined-account shielded-pool tree (state sub-tree +
/// address sub-tree co-located). Tree creation is admin-gated: `authority` must
/// be the signer named by the canonical protocol config, otherwise anyone could
/// stand up a rogue tree and drain the shared vault against roots they control.
/// `owner` becomes the access-metadata owner of the tree.
pub struct CreateTree {
    pub authority: Pubkey,
    pub tree: Pubkey,
    pub owner: Pubkey,
}

impl CreateTree {
    pub fn instruction(&self) -> Instruction {
        self.build_instruction(None)
    }

    /// Build a create-tree instruction with custom nullifier-tree params.
    /// Tree creation remains authority-gated, and the program validates the
    /// account layout during initialization.
    pub fn instruction_with_nullifier_params(
        &self,
        params: InitAddressTreeAccountsInstructionData,
    ) -> Instruction {
        self.build_instruction(Some(params))
    }

    fn build_instruction(
        &self,
        params: Option<InitAddressTreeAccountsInstructionData>,
    ) -> Instruction {
        let mut data = vec![tag::CREATE_TREE];
        CreateTreeData {
            owner: self.owner.to_bytes(),
        }
        .serialize(&mut data)
        .expect("shielded-pool instruction serialization is infallible");
        if let Some(params) = params {
            params
                .serialize(&mut data)
                .expect("shielded-pool instruction serialization is infallible");
        }

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new_readonly(pda::protocol_config(), false),
                AccountMeta::new(self.tree, false),
            ],
            data,
        }
    }
}
