use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{instruction::tag, pda, PROGRAM_ID_PUBKEY};

pub struct CreateAssetCounter {
    pub authority: Pubkey,
}

impl CreateAssetCounter {
    pub fn instruction(&self) -> Instruction {
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new(self.authority, true),
                AccountMeta::new_readonly(pda::protocol_config(), false),
                AccountMeta::new(pda::spl_asset_counter(), false),
                AccountMeta::new_readonly(Pubkey::default(), false),
            ],
            data: vec![tag::CREATE_ASSET_COUNTER],
        }
    }
}
