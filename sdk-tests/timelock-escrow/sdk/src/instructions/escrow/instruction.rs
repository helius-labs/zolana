use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use timelock_escrow_program::instructions::escrow::owner_tags;
use zolana_interface::instruction::instruction_data::transact::TransactIxData;

use super::EscrowTransaction;
use crate::{
    err, escrow_authority, tag, zk_program::program_instruction, EscrowIxData, EscrowProof,
};

pub struct Escrow {
    pub transaction: EscrowTransaction,
    pub spp_proof: TransactIxData,
    pub escrow_proof: EscrowProof,
}

impl Escrow {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            transaction,
            spp_proof,
            escrow_proof,
        } = self;
        let authority = *escrow_authority().pda();
        let proven = transaction.transaction.accept(spp_proof)?;
        let creator = *proven.built().payer();
        let transact = proven.transact(owner_tags(&creator, &authority))?;
        let data = wincode::serialize(&EscrowIxData {
            proof: escrow_proof,
            transact,
        })
        .map_err(err)?;
        let mut accounts = vec![AccountMeta::new(creator, true)];
        accounts.extend(proven.spp_accounts(&[authority])?);
        Ok(program_instruction(
            timelock_escrow_program::ID,
            tag::ESCROW,
            &data,
            accounts,
        ))
    }
}
