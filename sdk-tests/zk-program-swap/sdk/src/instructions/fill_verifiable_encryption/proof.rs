use anyhow::{bail, Result};
use swap_program::instructions::fill_verifiable_encryption::FillVerifiableEncryptionPublicInput;
use swap_prover::{
    FillVerifiableEncryptionProofInputs, OrderTermsProofInput, FILL_MODE_VERIFIABLE,
};
use zolana_transaction::{
    instructions::transact::{OutputUtxo, PrivateTxHash},
    ProofInputUtxo,
};

use super::encryption::destination_ciphertext_with_hash;
use crate::{err, order::OrderUtxo, shared::check_output_utxo};

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
        let taker = check_output_utxo(
            "taker_in",
            &self.taker_in,
            &terms.destination_mint,
            terms.destination_amount,
        )?;
        let source_owner = check_output_utxo(
            "source_output",
            &self.source_output,
            &self.escrow.source_mint,
            self.escrow.source_amount,
        )?;
        if source_owner != taker {
            bail!("source output owner does not match the taker input owner");
        }
        let destination_owner = check_output_utxo(
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
        let order = OrderTermsProofInput::try_from(terms)?;
        let escrow = ProofInputUtxo::try_from(&self.escrow.to_input_utxo()?).map_err(err)?;
        let taker_in = ProofInputUtxo::try_from(&self.taker_in).map_err(err)?;
        let source_output = ProofInputUtxo::try_from(&self.source_output).map_err(err)?;
        let destination_output = ProofInputUtxo::try_from(&self.destination_output).map_err(err)?;
        let private_tx_hash = PrivateTxHash::new(
            &[escrow.hash().map_err(err)?, taker_in.hash().map_err(err)?],
            &[
                source_output.hash().map_err(err)?,
                destination_output.hash().map_err(err)?,
            ],
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
            escrow,
            taker_in,
            source_output,
            destination_output,
            external_data_hash: self.external_data_hash,
        })
    }
}
