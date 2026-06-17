use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{instruction::tag, pda, SHIELDED_POOL_PROGRAM_ID};

pub fn create_asset_counter(authority: Pubkey) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(pda::spl_asset_counter(), false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ],
        data: vec![tag::CREATE_ASSET_COUNTER],
    }
}
