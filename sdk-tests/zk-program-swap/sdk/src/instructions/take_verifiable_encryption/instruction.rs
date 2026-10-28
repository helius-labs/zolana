use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use spr_interface::{
    instruction::instruction_data::transact::TransactIxData, SHIELDED_POOL_PROGRAM_ID,
};
use spr_program::instruction::nullifier_pda_accounts;
use swap_program::instructions::take_verifiable_encryption::TakeVerifiableEncryptionIxData;

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

        let nullifier_pdas = nullifier_pda_accounts(
            &tree,
            spp_proof.inputs.iter().map(|input| &input.nullifier_hash),
        );
        let serialized_ix = wincode::serialize(&TakeVerifiableEncryptionIxData {
            proof: take_proof,
            transact: spp_proof,
        })
        .map_err(err)?;

        let mut accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new(tree, false),
        ];
        accounts.extend(nullifier_pdas);
        // The order is the first input; the taker's own note is the second.
        // The taker also pays, but must appear explicitly in the owner slots.
        accounts.push(AccountMeta::new_readonly(order_authority_pda(), false));
        accounts.push(AccountMeta::new_readonly(payer, true));
        let mut instruction_data = vec![tag::TAKE_VERIFIABLE_ENCRYPTION];
        instruction_data.extend_from_slice(&serialized_ix);
        Ok(Instruction {
            program_id: swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
