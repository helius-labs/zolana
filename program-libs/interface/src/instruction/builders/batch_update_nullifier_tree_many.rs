use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{encode_instruction, tag, BatchUpdateNullifierTreeData},
    pda, PROGRAM_ID_PUBKEY,
};

/// Batch incarnation of nullifier-tree ZKP update (tag 52).
pub struct BatchUpdateNullifierTreeMany {
    pub authority: Pubkey,
    pub tree: Pubkey,
    pub reimbursement_recipient: Pubkey,
    pub updates: Vec<BatchUpdateNullifierTreeData>,
}

impl BatchUpdateNullifierTreeMany {
    pub fn instruction(&self) -> Instruction {
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new_readonly(pda::protocol_config(), false),
                AccountMeta::new(self.tree, false),
                AccountMeta::new(self.reimbursement_recipient, false),
                AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
            ],
            data: encode_instruction(tag::BATCH_UPDATE_NULLIFIER_TREE_MANY, &self.updates),
        }
    }
}
