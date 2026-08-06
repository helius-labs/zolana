use anyhow::{anyhow, Result};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, SHIELDED_POOL_PROGRAM_ID,
};

use crate::{err, tag, CreateEscrowIxData, EscrowOpenProof};

pub struct CreateEscrow {
    pub owner: Pubkey,
    pub pair: Pubkey,
    pub liquidity: Pubkey,
    pub escrow: Pubkey,
    pub tree: Pubkey,
    pub proof: EscrowOpenProof,
    pub order_commitment: [u8; 32],
    pub created_at_unix_ts: i64,
    pub transact: TransactIxData,
}

impl CreateEscrow {
    pub fn instruction(mut self) -> Result<Instruction> {
        // Forwarded tail: payer=0, input tree=1, output tree=2,
        // system=3, source owner=4, SPP=5.
        self.transact
            .inputs
            .first_mut()
            .ok_or_else(|| anyhow!("create_escrow requires one source input"))?
            .eddsa_signer_index = 4;
        let ix_data = CreateEscrowIxData {
            proof: self.proof,
            order_commitment: self.order_commitment,
            created_at_unix_ts: self.created_at_unix_ts,
            transact: self.transact,
        };
        let mut data = vec![tag::CREATE_ESCROW];
        data.extend_from_slice(&wincode::serialize(&ix_data).map_err(err)?);
        Ok(Instruction {
            program_id: dynamic_swap_program::ID,
            accounts: vec![
                AccountMeta::new(self.owner, true),
                AccountMeta::new_readonly(self.pair, false),
                AccountMeta::new(self.liquidity, false),
                AccountMeta::new(self.escrow, false),
                AccountMeta::new_readonly(solana_system_interface::program::ID, false),
                AccountMeta::new(self.owner, true),
                AccountMeta::new(self.tree, false),
                AccountMeta::new(self.tree, false),
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new_readonly(self.owner, true),
                AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
            ],
            data,
        })
    }
}
