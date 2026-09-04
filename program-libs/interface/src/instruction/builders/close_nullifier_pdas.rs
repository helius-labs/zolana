use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{builders::transact::nullifier_pda_accounts, tag},
    pda, PROGRAM_ID_PUBKEY,
};

pub struct CloseNullifierPdas {
    pub authority: Pubkey,
    pub tree: Pubkey,
    pub reimbursement_recipient: Pubkey,
    pub nullifiers: Vec<[u8; 32]>,
}

impl CloseNullifierPdas {
    pub fn instruction(&self) -> Instruction {
        let mut accounts = vec![
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(self.tree, false),
            AccountMeta::new(self.reimbursement_recipient, false),
        ];
        accounts.extend(nullifier_pda_accounts(&self.tree, self.nullifiers.iter()));

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: vec![tag::CLOSE_NULLIFIER_PDAS],
        }
    }
}
