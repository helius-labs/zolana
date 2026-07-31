use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_program::instructions::cancel::CancelIxData;
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, SHIELDED_POOL_PROGRAM_ID,
};

use crate::{err, order_authority_pda, tag, CancelProof};

pub struct Cancel {
    /// The maker's ed25519 pubkey, a dedicated readonly signer the swap program
    /// checks against the cancel proof's committed maker.
    pub maker: Pubkey,
    pub payer: Pubkey,
    pub tree: Pubkey,
    pub cancel_proof: CancelProof,
    pub order_expiry: u64,
    pub spp_proof: TransactIxData,
}

impl Cancel {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            maker,
            payer,
            tree,
            cancel_proof,
            order_expiry,
            spp_proof,
        } = self;

        let serialized_ix = wincode::serialize(&CancelIxData {
            proof: cancel_proof,
            order_expiry,
            transact: spp_proof,
        })
        .map_err(err)?;

        // The maker is a dedicated readonly signer after the fee payer; the swap
        // program checks its pubkey against the cancel proof's committed maker.
        let accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(maker, true),
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(order_authority_pda(), false),
        ];
        let mut instruction_data = vec![tag::CANCEL];
        instruction_data.extend_from_slice(&serialized_ix);
        Ok(Instruction {
            program_id: swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
