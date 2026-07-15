use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_program::instructions::fill::FillIxData;
use zolana_interface::instruction::instruction_data::transact::TransactIxData;

use crate::{err, escrow_authority_pda, program_id_pubkey, spp_program_meta, tag, FillProof};

pub struct Fill {
    pub payer: Pubkey,
    pub tree: Pubkey,
    pub fill_proof: FillProof,
    pub spp_proof: TransactIxData,
}

const ESCROW_AUTHORITY_SIGNER_INDEX: u8 = 2;

impl Fill {
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

        let data = wincode::serialize(&FillIxData {
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
        let mut instruction_data = vec![tag::FILL];
        instruction_data.extend_from_slice(&data);
        Ok(Instruction {
            program_id: program_id_pubkey(),
            accounts,
            data: instruction_data,
        })
    }
}
