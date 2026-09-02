use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_tree::{NullifierTreeInitParams, TreeFeeSchedule};

use crate::{
    instruction::{encode_instruction, tag, CreateTreeData},
    pda,
    state::tree_creation_step_count,
    PROGRAM_ID_PUBKEY,
};

pub struct CreateTree {
    pub payer: Pubkey,
    pub authority: Pubkey,
    pub tree_id: u16,
    pub nullifier_params: NullifierTreeInitParams,
    pub fees: TreeFeeSchedule,
}

impl CreateTree {
    pub fn tree(&self) -> Pubkey {
        pda::tree(self.tree_id)
    }

    pub fn instructions(&self) -> Vec<Instruction> {
        let step = self.allocation_step();
        (0..tree_creation_step_count())
            .map(|_| step.clone())
            .collect()
    }

    pub fn allocation_step(&self) -> Instruction {
        let data = CreateTreeData {
            tree_id: self.tree_id,
            nullifier_params: self.nullifier_params,
            fees: self.fees,
        };
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new(pda::protocol_config(), false),
                AccountMeta::new(self.tree(), false),
                AccountMeta::new_readonly(Pubkey::default(), false),
            ],
            data: encode_instruction(tag::CREATE_TREE, &data),
        }
    }
}
