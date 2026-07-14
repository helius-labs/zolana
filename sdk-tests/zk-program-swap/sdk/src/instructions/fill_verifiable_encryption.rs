use anyhow::{bail, Result};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_prover::FillVerifiableEncryptionProofInputs;
use wincode::SchemaWrite;
use zolana_interface::instruction::instruction_data::transact::TransactIxData;
use zolana_transaction::instructions::transact::OutputUtxo;

use crate::{
    err, escrow_authority_pda,
    order::{ensure_payout, BlindingField, DataHash, OrderUtxo},
    program_id_pubkey, spp_program_meta, tag, FillVerifiableEncryptionProof,
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaWrite)]
pub struct FillVerifiableEncryptionIxData {
    pub proof: FillVerifiableEncryptionProof,
    pub transact: TransactIxData,
}

pub struct FillVerifiableEncryptionProofInputParams {
    pub escrow: OrderUtxo,
    pub taker_in: OutputUtxo,
    pub source_output: OutputUtxo,
    pub destination_output: OutputUtxo,
    pub external_data_hash: [u8; 32],
}

impl FillVerifiableEncryptionProofInputParams {
    pub fn into_proof_inputs(&self) -> Result<FillVerifiableEncryptionProofInputs> {
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
        Ok(FillVerifiableEncryptionProofInputs {
            source_mint: *self.escrow.source_mint.as_array(),
            destination_mint: *terms.destination_mint.as_array(),
            source_amount: self.escrow.source_amount,
            escrow_authority: *escrow_authority_pda().as_array(),
            escrow_blinding: self.escrow.blinding.to_field(),
            destination_amount: terms.destination_amount,
            maker_owner_hash: terms.destination.owner_hash().map_err(err)?,
            maker_viewing_pk: *terms.destination.viewing_pubkey.as_bytes(),
            expiry: terms.expiry,
            taker_pk_fe: terms.taker.data_hash()?,
            taker_nullifier_pk: taker.nullifier_pubkey,
            taker_in_blinding: self.taker_in.blinding.to_field(),
            destination_output_blinding: self.destination_output.blinding.to_field(),
            source_output_blinding: self.source_output.blinding.to_field(),
            external_data_hash: self.external_data_hash,
        })
    }
}

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
