use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_program::instructions::cancel::CancelIxData;
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, SHIELDED_POOL_PROGRAM_ID,
};

use crate::{err, escrow_authority_pda, tag, CancelProof};

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

/// The escrow (input 0) is owned by the escrow-authority PDA appended readonly
/// after `tree`; the swap program signs for it via `invoke_signed`. The signer
/// index selects the account whose pubkey the SPP proof's input_owner_pk_hash
/// must match; it is not itself a proof public input, so overriding it post-proof
/// is safe.
const ESCROW_AUTHORITY_SIGNER_INDEX: u8 = 2;

impl Cancel {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            maker,
            payer,
            tree,
            cancel_proof,
            order_expiry,
            mut spp_proof,
        } = self;
        if let Some(escrow_input) = spp_proof.inputs.get_mut(0) {
            escrow_input.eddsa_signer_index = ESCROW_AUTHORITY_SIGNER_INDEX;
        }

        let data = wincode::serialize(&CancelIxData {
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
            AccountMeta::new_readonly(escrow_authority_pda(), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
        ];
        let mut instruction_data = vec![tag::CANCEL];
        instruction_data.extend_from_slice(&data);
        Ok(Instruction {
            program_id: swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
