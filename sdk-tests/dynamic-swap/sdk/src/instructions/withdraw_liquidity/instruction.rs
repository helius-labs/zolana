use anyhow::Result;
use dynamic_swap_program::instructions::withdraw_liquidity::PoolUpdateProof;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::instruction::instruction_data::transact::TransactIxData;

use crate::{err, tag, WithdrawLiquidityIxData};

pub struct WithdrawLiquidity {
    pub authority: Pubkey,
    pub pair: Pubkey,
    pub liquidity: Pubkey,
    pub proof: PoolUpdateProof,
    pub available_slots: u64,
    pub refresh_capacity: bool,
    pub transact: TransactIxData,
    /// The exact SPP `transact` CPI account tail this instruction forwards
    /// verbatim via `AccountIterator::remaining()`: tree, any public-amount
    /// withdrawal accounts, and the shielded-pool program id last.
    pub spp_accounts: Vec<AccountMeta>,
}

impl WithdrawLiquidity {
    pub fn instruction(self) -> Result<Instruction> {
        let ix_data = WithdrawLiquidityIxData {
            proof: self.proof,
            available_slots: self.available_slots,
            refresh_capacity: self.refresh_capacity,
            transact: self.transact,
        };
        let serialized = wincode::serialize(&ix_data).map_err(err)?;

        let mut instruction_data = vec![tag::WITHDRAW_LIQUIDITY];
        instruction_data.extend_from_slice(&serialized);

        let mut accounts = vec![
            AccountMeta::new(self.authority, true),
            AccountMeta::new_readonly(self.pair, false),
            AccountMeta::new(self.liquidity, false),
        ];
        accounts.extend(self.spp_accounts);

        Ok(Instruction {
            program_id: dynamic_swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
