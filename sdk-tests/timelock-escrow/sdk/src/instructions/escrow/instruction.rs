use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, SHIELDED_POOL_PROGRAM_ID,
};

use crate::{err, tag, EscrowIxData, EscrowProof};

pub struct Escrow {
    pub payer: Pubkey,
    pub tree: Pubkey,
    pub escrow_proof: EscrowProof,
    pub spp_proof: TransactIxData,
}

impl Escrow {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            payer,
            tree,
            escrow_proof,
            spp_proof,
        } = self;

        let serialized_ix = wincode::serialize(&EscrowIxData {
            proof: escrow_proof,
            transact: spp_proof,
        })
        .map_err(err)?;

        let accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
        ];
        let mut instruction_data = vec![tag::ESCROW];
        instruction_data.extend_from_slice(&serialized_ix);
        Ok(Instruction {
            program_id: timelock_escrow_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
