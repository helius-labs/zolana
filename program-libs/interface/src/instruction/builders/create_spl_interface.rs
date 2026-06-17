use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{instruction::tag, pda, PROGRAM_ID_PUBKEY, SPL_TOKEN_PROGRAM_ID};

pub struct CreateSplInterface {
    pub authority: Pubkey,
    pub mint: Pubkey,
}

impl CreateSplInterface {
    pub fn instruction(&self) -> Instruction {
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new(self.authority, true),
                AccountMeta::new_readonly(pda::protocol_config(), false),
                AccountMeta::new(pda::spl_asset_counter(), false),
                AccountMeta::new(pda::spl_asset_registry(&self.mint), false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new(pda::spl_asset_vault(&self.mint), false),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new_readonly(Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID), false),
            ],
            data: vec![tag::CREATE_SPL_INTERFACE],
        }
    }
}
