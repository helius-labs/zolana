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

/// The order utxo (input 0) is owned by the order-authority PDA appended readonly
/// after `tree`; the swap program signs for it via `invoke_signed`. The taker
/// input is signed by the SPP payer (account index 0). The signer index
/// selects the account whose pubkey the SPP proof's input_owner_pk_hash must
/// match; it is not itself a proof public input, so overriding it post-proof is
/// safe.
const ORDER_AUTHORITY_SIGNER_INDEX: u8 = 2;

impl TakeVerifiableEncryption {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            payer,
            tree,
            take_proof,
            mut spp_proof,
        } = self;
        if let Some(order_input_utxo) = spp_proof.inputs.get_mut(0) {
            order_input_utxo.eddsa_signer_index = ORDER_AUTHORITY_SIGNER_INDEX;
        }

        let serialized_ix = wincode::serialize(&TakeVerifiableEncryptionIxData {
            proof: take_proof,
            transact: spp_proof,
        })
        .map_err(err)?;

        let accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(order_authority_pda(), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
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
