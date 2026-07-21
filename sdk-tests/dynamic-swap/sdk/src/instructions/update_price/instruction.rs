use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{err, tag, UpdatePriceData};

pub struct UpdatePrice {
    pub authority: Pubkey,
    pub pair: Pubkey,
    pub price: u64,
}

impl UpdatePrice {
    pub fn instruction(self) -> Result<Instruction> {
        let data = UpdatePriceData { price: self.price };

        let mut instruction_data = vec![tag::UPDATE_PRICE];
        instruction_data.extend_from_slice(&borsh::to_vec(&data).map_err(err)?);

        let accounts = vec![
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new(self.pair, false),
        ];
        Ok(Instruction {
            program_id: dynamic_swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
