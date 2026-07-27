use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, SHIELDED_POOL_PROGRAM_ID,
};

use crate::{err, order_authority_pda, tag, MakeIxData, MakeProof};

/// Batch incarnation of make: compose hub (policy + SPP in one RLC).
pub struct MakeBatch {
    pub payer: Pubkey,
    /// Packed standard make VK (`pack_standard_vk`).
    pub foreign_vk: Pubkey,
    pub tree: Pubkey,
    pub make_proof: MakeProof,
    pub spp_proof: TransactIxData,
}

impl MakeBatch {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            payer,
            foreign_vk,
            tree,
            make_proof,
            mut spp_proof,
        } = self;

        if let Some(marker) = spp_proof.messages.first_mut() {
            marker.data = Vec::new();
        }
        // After foreign_vk, SPP account order matches solo: payer, trees, system,
        // order_authority → signer index 4 is still the order authority.
        for input in &mut spp_proof.inputs {
            input.eddsa_signer_index = 4;
        }

        let serialized_ix = wincode::serialize(&MakeIxData {
            proof: make_proof,
            transact: spp_proof,
        })
        .map_err(err)?;

        let accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(foreign_vk, false),
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(order_authority_pda(), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
        ];
        let mut instruction_data = vec![tag::MAKE_BATCH];
        instruction_data.extend_from_slice(&serialized_ix);
        Ok(Instruction {
            program_id: swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
