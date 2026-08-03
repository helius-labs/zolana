use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{instruction::tag, pda, PROGRAM_ID_PUBKEY};

pub struct CreateSplInterface {
    pub authority: Pubkey,
    pub mint: Pubkey,
    pub token_program: Pubkey,
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
                AccountMeta::new(pda::spl_interface(&self.mint), false),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new_readonly(self.token_program, false),
            ],
            data: vec![tag::CREATE_SPL_INTERFACE],
        }
    }
}
