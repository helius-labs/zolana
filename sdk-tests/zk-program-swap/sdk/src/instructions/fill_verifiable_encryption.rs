use anyhow::{bail, Result};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_program::instructions::fill_verifiable_encryption::verify::FillVerifiableEncryptionPublicInput;
use swap_prover::{FillVerifiableEncryptionProofInputs, FILL_MODE_VERIFIABLE};
use wincode::SchemaWrite;
use zolana_interface::instruction::instruction_data::transact::TransactIxData;
use zolana_transaction::instructions::transact::{OutputUtxo, PrivateTxHash};

use crate::{
    err, escrow_authority_pda,
    order::{ensure_payout, OrderUtxo},
    program_id_pubkey, spp_program_meta, tag,
    witness::{destination_ciphertext_with_hash, escrow_owner_hash, order_data_hash, PlainUtxo},
    FillVerifiableEncryptionProof,
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
    pub fn to_proof_inputs(&self) -> Result<FillVerifiableEncryptionProofInputs> {
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
        if terms.fill_mode != FILL_MODE_VERIFIABLE {
            bail!("order fill_mode does not authorize the verifiable-encryption fill");
        }
        let order = terms.field_elements()?;
        let taker_owner_hash = taker.owner_hash().map_err(err)?;
        let escrow = PlainUtxo {
            owner_hash: escrow_owner_hash(escrow_authority_pda().as_array())?,
            mint: self.escrow.source_mint,
            amount: self.escrow.source_amount,
            blinding: self.escrow.blinding,
            data_hash: order_data_hash(&order)?,
        };
        let taker_in = PlainUtxo {
            owner_hash: taker_owner_hash,
            mint: terms.destination_mint,
            amount: terms.destination_amount,
            blinding: self.taker_in.blinding,
            data_hash: [0u8; 32],
        };
        let source_output = PlainUtxo {
            owner_hash: taker_owner_hash,
            mint: self.escrow.source_mint,
            amount: self.escrow.source_amount,
            blinding: self.source_output.blinding,
            data_hash: [0u8; 32],
        };
        let destination_output = PlainUtxo {
            owner_hash: order.maker_owner_hash,
            mint: terms.destination_mint,
            amount: terms.destination_amount,
            blinding: self.destination_output.blinding,
            data_hash: [0u8; 32],
        };
        let private_tx_hash = PrivateTxHash::new(
            &[escrow.hash()?, taker_in.hash()?],
            &[source_output.hash()?, destination_output.hash()?],
            &self.external_data_hash,
        )
        .hash()
        .map_err(err)?;
        let (ciphertext, _) = destination_ciphertext_with_hash(
            &self.escrow.blinding,
            &terms.destination_mint,
            terms.destination_amount,
            &self.destination_output.blinding,
        )?;
        let public_input_hash = FillVerifiableEncryptionPublicInput {
            private_tx_hash: &private_tx_hash,
            expiry: terms.expiry,
            destination_ciphertext: &ciphertext,
        }
        .hash()
        .map_err(err)?;
        Ok(FillVerifiableEncryptionProofInputs {
            public_input_hash,
            private_tx_hash,
            order,
            taker_nullifier_pk: taker.nullifier_pubkey,
            escrow: escrow.field_elements()?,
            taker_in: taker_in.field_elements()?,
            source_output: source_output.field_elements()?,
            destination_output: destination_output.field_elements()?,
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
