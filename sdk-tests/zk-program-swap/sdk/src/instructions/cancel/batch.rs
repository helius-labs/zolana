use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_program::instructions::cancel::CancelIxData;
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, SHIELDED_POOL_PROGRAM_ID,
};

use crate::{err, order_authority_pda, tag, CancelProof};

/// Batch incarnation of cancel: compose hub.
pub struct CancelBatch {
    pub maker: Pubkey,
    pub payer: Pubkey,
    pub foreign_vk: Pubkey,
    pub tree: Pubkey,
    pub cancel_proof: CancelProof,
    pub order_expiry: u64,
    pub spp_proof: TransactIxData,
}

const ORDER_AUTHORITY_SIGNER_INDEX: u8 = 4;

impl CancelBatch {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            maker,
            payer,
            foreign_vk,
            tree,
            cancel_proof,
            order_expiry,
            mut spp_proof,
        } = self;
        if let Some(order_input_utxo) = spp_proof.inputs.get_mut(0) {
            order_input_utxo.eddsa_signer_index = ORDER_AUTHORITY_SIGNER_INDEX;
        }

        let serialized_ix = wincode::serialize(&CancelIxData {
            proof: cancel_proof,
            order_expiry,
            transact: spp_proof,
        })
        .map_err(err)?;

        let accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(maker, true),
            AccountMeta::new_readonly(foreign_vk, false),
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(order_authority_pda(), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
        ];
        let mut instruction_data = vec![tag::CANCEL_BATCH];
        instruction_data.extend_from_slice(&serialized_ix);
        Ok(Instruction {
            program_id: swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
