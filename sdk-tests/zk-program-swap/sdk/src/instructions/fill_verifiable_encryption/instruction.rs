use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_program::instructions::fill_verifiable_encryption::FillVerifiableEncryptionIxData;
use zolana_interface::instruction::instruction_data::transact::TransactIxData;

use crate::{
    err, escrow_authority_pda, program_id_pubkey, spp_program_meta, tag,
    FillVerifiableEncryptionProof,
};

pub struct FillVerifiableEncryption {
    pub payer: Pubkey,
    pub tree: Pubkey,
    pub fill_proof: FillVerifiableEncryptionProof,
    pub spp_proof: TransactIxData,
}

/// The escrow (input 0) is owned by the escrow-authority PDA appended readonly
/// after `tree`; the swap program signs for it via `invoke_signed`. The taker
/// input is signed by the SPP payer (account index 0). The signer index
/// selects the account whose pubkey the SPP proof's input_owner_pk_hash must
/// match; it is not itself a proof public input, so overriding it post-proof is
/// safe.
const ESCROW_AUTHORITY_SIGNER_INDEX: u8 = 2;

impl FillVerifiableEncryption {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            payer,
            tree,
            fill_proof,
            mut spp_proof,
        } = self;
        if let Some(escrow_input) = spp_proof.inputs.get_mut(0) {
            escrow_input.eddsa_signer_index = ESCROW_AUTHORITY_SIGNER_INDEX;
        }

        let data = wincode::serialize(&FillVerifiableEncryptionIxData {
            proof: fill_proof,
            transact: spp_proof,
        })
        .map_err(err)?;

        let accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(escrow_authority_pda(), false),
            spp_program_meta(),
        ];
        let mut instruction_data = vec![tag::FILL_VERIFIABLE_ENCRYPTION];
        instruction_data.extend_from_slice(&data);
        Ok(Instruction {
            program_id: program_id_pubkey(),
            accounts,
            data: instruction_data,
        })
    }
}
