use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{
        builders::transact::nullifier_pda_accounts, encode_instruction, tag, CloseNullifierPdasData,
    },
    PROGRAM_ID_PUBKEY,
};

pub struct CloseNullifierPdas {
    pub tree: Pubkey,
    pub nullifiers: Vec<[u8; 32]>,
}

impl CloseNullifierPdas {
    pub fn instruction(&self) -> Instruction {
        let data = CloseNullifierPdasData {
            nullifiers: self.nullifiers.clone(),
        };

        let mut accounts = vec![AccountMeta::new(self.tree, false)];
        accounts.extend(nullifier_pda_accounts(&self.tree, self.nullifiers.iter()));

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: encode_instruction(tag::CLOSE_NULLIFIER_PDAS, &data),
        }
    }
}
