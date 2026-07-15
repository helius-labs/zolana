use anyhow::{bail, Result};
use swap_program::instructions::take_verifiable_encryption::TakeVerifiableEncryptionPublicInput;
use swap_prover::{
    OrderTermsProofInput, TakeVerifiableEncryptionProofInputs, TAKE_MODE_VERIFIABLE,
};
use zolana_transaction::{
    instructions::transact::{PrivateTxHash, SppProofOutputUtxo},
    ProofInputUtxo,
};

use super::encryption::destination_ciphertext_with_hash;
use crate::{err, shared::check_output_utxo, state::OrderUtxo};

pub struct TakeVerifiableEncryptionProofInputParams {
    pub order_utxo: OrderUtxo,
    pub taker_in: SppProofOutputUtxo,
    pub source_output: SppProofOutputUtxo,
    pub destination_output: SppProofOutputUtxo,
    pub external_data_hash: [u8; 32],
}

impl TakeVerifiableEncryptionProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<TakeVerifiableEncryptionProofInputs> {
        let terms = &self.order_utxo.terms;
        let taker = check_output_utxo(
            "taker_in",
            &self.taker_in,
            &terms.destination_mint,
            terms.destination_amount,
        )?;
        let source_owner = check_output_utxo(
            "source_output",
            &self.source_output,
            &self.order_utxo.source_mint,
            self.order_utxo.source_amount,
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
        if terms.take_mode != TAKE_MODE_VERIFIABLE {
            bail!("order take_mode does not authorize the verifiable-encryption take");
        }
        let order = OrderTermsProofInput::try_from(terms)?;
        let order_utxo =
            ProofInputUtxo::try_from(&self.order_utxo.to_input_utxo()?).map_err(err)?;
        let taker_in = ProofInputUtxo::try_from(&self.taker_in).map_err(err)?;
        let source_output = ProofInputUtxo::try_from(&self.source_output).map_err(err)?;
        let destination_output = ProofInputUtxo::try_from(&self.destination_output).map_err(err)?;
        let private_tx_hash = PrivateTxHash::new(
            &[
                order_utxo.hash().map_err(err)?,
                taker_in.hash().map_err(err)?,
            ],
            &[
                source_output.hash().map_err(err)?,
                destination_output.hash().map_err(err)?,
            ],
            &self.external_data_hash,
        )
        .hash()
        .map_err(err)?;
        let (ciphertext, _) = destination_ciphertext_with_hash(
            &self.order_utxo.blinding,
            &terms.destination_mint,
            terms.destination_amount,
            &self.destination_output.blinding,
        )?;
        let public_input_hash = TakeVerifiableEncryptionPublicInput {
            private_tx_hash: &private_tx_hash,
            expiry: terms.expiry,
            destination_ciphertext: &ciphertext,
        }
        .hash()
        .map_err(err)?;
        Ok(TakeVerifiableEncryptionProofInputs {
            public_input_hash,
            private_tx_hash,
            order,
            taker_nullifier_pk: taker.nullifier_pubkey,
            order_utxo,
            taker_in,
            source_output,
            destination_output,
            external_data_hash: self.external_data_hash,
        })
    }
}
