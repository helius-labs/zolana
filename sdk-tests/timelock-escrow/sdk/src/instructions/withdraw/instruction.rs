use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use timelock_escrow_program::instructions::withdraw::owner_tags;
use zolana_interface::instruction::instruction_data::transact::TransactIxData;

use super::WithdrawTransaction;
use crate::{
    err, escrow_authority, tag, zk_program::program_instruction, WithdrawIxData, WithdrawProof,
};

pub struct Withdraw {
    pub transaction: WithdrawTransaction,
    pub spp_proof: TransactIxData,
    pub withdraw_proof: WithdrawProof,
}

impl Withdraw {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            transaction,
            spp_proof,
            withdraw_proof,
        } = self;
        let authority = *escrow_authority().pda();
        let creator = transaction.creator()?;
        let unlock_timestamp = transaction.escrow_utxo.state().unlock_timestamp;
        let proven = transaction.transaction.accept(spp_proof)?;
        let caller = *proven.built().payer();
        let transact = proven.transact(owner_tags(&creator))?;
        let data = wincode::serialize(&WithdrawIxData {
            proof: withdraw_proof,
            unlock_timestamp,
            transact,
        })
        .map_err(err)?;
        let mut accounts = vec![
            AccountMeta::new(caller, true),
            AccountMeta::new_readonly(creator, true),
        ];
        accounts.extend(proven.spp_accounts(&[authority])?);
        Ok(program_instruction(
            timelock_escrow_program::ID,
            tag::WITHDRAW,
            &data,
            accounts,
        ))
    }
}
