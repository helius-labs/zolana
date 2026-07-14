use anyhow::{bail, Result};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_prover::FillProofInputs;
use wincode::SchemaWrite;
use zolana_interface::instruction::instruction_data::transact::TransactIxData;
use zolana_transaction::instructions::transact::OutputUtxo;

use crate::{
    err, escrow_authority_pda,
    order::{ensure_payout, BlindingField, DataHash, OrderUtxo},
    program_id_pubkey, spp_program_meta, tag, FillProof,
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaWrite)]
pub struct FillIxData {
    pub proof: FillProof,
    pub transact: TransactIxData,
}

pub struct FillProofInputParams {
    pub escrow: OrderUtxo,
    pub taker_in: OutputUtxo,
    pub source_output: OutputUtxo,
    pub destination_output: OutputUtxo,
    pub external_data_hash: [u8; 32],
}

impl FillProofInputParams {
    pub fn into_proof_inputs(&self) -> Result<FillProofInputs> {
        let terms = &self.escrow.terms;
        let taker = ensure_payout(
            "taker_in",
            &self.taker_in,
            &terms.destination_mint,
            terms.destination_amount,
        )?;
        let source_owner = ensure_payout(
            "source_output",
            &self.source_output,
            &self.escrow.source_mint,
            self.escrow.source_amount,
        )?;
        if source_owner != taker {
            bail!("source output owner does not match the taker input owner");
        }
        let destination_owner = ensure_payout(
            "destination_output",
            &self.destination_output,
            &terms.destination_mint,
            terms.destination_amount,
        )?;
        if destination_owner != terms.destination {
            bail!("destination output owner does not match the order destination");
        }
        if self.destination_output.blinding != self.escrow.derived_destination_blinding()? {
            bail!("destination output blinding does not match the derived blinding");
        }
        Ok(FillProofInputs {
            source_mint: *self.escrow.source_mint.as_array(),
            source_amount: self.escrow.source_amount,
            escrow_authority: *escrow_authority_pda().as_array(),
            escrow_blinding: self.escrow.blinding.to_field(),
            destination_mint: *terms.destination_mint.as_array(),
            destination_amount: terms.destination_amount,
            maker_owner_hash: terms.destination.owner_hash().map_err(err)?,
            maker_viewing_pk: *terms.destination.viewing_pubkey.as_bytes(),
            expiry: terms.expiry,
            taker_pk_fe: terms.taker.data_hash()?,
            taker_address: taker.owner_hash().map_err(err)?,
            taker_in_blinding: self.taker_in.blinding.to_field(),
            source_output_blinding: self.source_output.blinding.to_field(),
            external_data_hash: self.external_data_hash,
        })
    }
}

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
