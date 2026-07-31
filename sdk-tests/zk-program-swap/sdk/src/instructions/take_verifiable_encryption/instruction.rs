use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_program::instructions::take_verifiable_encryption::TakeVerifiableEncryptionIxData;
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, SHIELDED_POOL_PROGRAM_ID,
};

use crate::{err, order_authority_pda, tag, TakeVerifiableEncryptionProof};

pub struct TakeVerifiableEncryption {
    pub payer: Pubkey,
    pub tree: Pubkey,
    pub take_proof: TakeVerifiableEncryptionProof,
    pub spp_proof: TransactIxData,
}

impl TakeVerifiableEncryption {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            payer,
            tree,
            take_proof,
            spp_proof,
        } = self;

        let serialized_ix = wincode::serialize(&TakeVerifiableEncryptionIxData {
            proof: take_proof,
            transact: spp_proof,
        })
        .map_err(err)?;

        let accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(order_authority_pda(), false),
        ];
        let mut instruction_data = vec![tag::TAKE_VERIFIABLE_ENCRYPTION];
        instruction_data.extend_from_slice(&serialized_ix);
        Ok(Instruction {
            program_id: swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
