use anyhow::{anyhow, Result};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, SHIELDED_POOL_PROGRAM_ID,
};

use crate::{err, escrow_authority_pda, pool_authority_pda, tag, SettleIxData, SettleProof};

pub struct Settle {
    pub caller: Pubkey,
    pub pair: Pubkey,
    pub liquidity: Pubkey,
    pub escrow: Pubkey,
    pub tree: Pubkey,
    pub proof: SettleProof,
    pub available_slots: u64,
    pub transact: TransactIxData,
}

impl Settle {
    pub fn instruction(mut self) -> Result<Instruction> {
        let route = |transact: &mut TransactIxData, input: usize, signer: u8| -> Result<()> {
            transact
                .inputs
                .get_mut(input)
                .ok_or_else(|| anyhow!("settle input {input} missing"))?
                .eddsa_signer_index = signer;
            Ok(())
        };
        route(&mut self.transact, 0, 4)?;
        route(&mut self.transact, 1, 5)?;
        let ix_data = SettleIxData {
            proof: self.proof,
            available_slots: self.available_slots,
            transact: self.transact,
        };
        let mut data = vec![tag::SETTLE];
        data.extend_from_slice(&wincode::serialize(&ix_data).map_err(err)?);
        Ok(Instruction {
            program_id: dynamic_swap_program::ID,
            accounts: vec![
                AccountMeta::new(self.caller, true),
                AccountMeta::new_readonly(self.pair, false),
                AccountMeta::new(self.liquidity, false),
                AccountMeta::new(self.escrow, false),
                AccountMeta::new(self.caller, true),
                AccountMeta::new(self.tree, false),
                AccountMeta::new(self.tree, false),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new_readonly(escrow_authority_pda(&self.pair), false),
                AccountMeta::new_readonly(pool_authority_pda(&self.pair), false),
                AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
            ],
            data,
        })
    }
}
