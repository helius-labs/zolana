use anyhow::{anyhow, Result};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, SHIELDED_POOL_PROGRAM_ID,
};

use crate::{err, escrow_authority_pda, tag, RefundExpiredIxData, RefundProof};

pub struct RefundExpired {
    pub caller: Pubkey,
    pub pair: Pubkey,
    pub liquidity: Pubkey,
    pub escrow: Pubkey,
    pub tree: Pubkey,
    pub proof: RefundProof,
    pub transact: TransactIxData,
}

impl RefundExpired {
    pub fn instruction(mut self) -> Result<Instruction> {
        self.transact
            .inputs
            .first_mut()
            .ok_or_else(|| anyhow!("refund requires one order input"))?
            .eddsa_signer_index = 4;
        let ix_data = RefundExpiredIxData {
            proof: self.proof,
            transact: self.transact,
        };
        let mut data = vec![tag::REFUND_EXPIRED];
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
                AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
            ],
            data,
        })
    }
}
