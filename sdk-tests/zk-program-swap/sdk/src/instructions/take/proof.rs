use anyhow::{bail, Result};
use swap_program::instructions::{shared::u64_to_field, take::TakePublicInput};
use swap_prover::{
    OrderTermsProofInput, TakeProofInputs, DESTINATION_BLINDING_DOMAIN, TAKE_MODE_DERIVED,
};
use zolana_keypair::{constants::BLINDING_LEN, hash::poseidon};
use zolana_transaction::{
    instructions::transact::{OutputUtxo, PrivateTxHash},
    utxo::Blinding,
    ProofInputUtxo,
};

use crate::{
    err,
    shared::{check_output_utxo, to_blinding_array},
    state::OrderUtxo,
};

pub fn derive_destination_blinding(escrow_blinding: &Blinding) -> Result<Blinding> {
    let domain = u64_to_field(DESTINATION_BLINDING_DOMAIN);
    let derived = poseidon(&[&to_blinding_array(escrow_blinding), &domain]).map_err(err)?;
    let mut blinding = [0u8; BLINDING_LEN];
    blinding.copy_from_slice(derived.get(1..32).ok_or_else(|| err("blinding tail"))?);
    Ok(blinding)
}

pub struct TakeProofInputParams {
    pub escrow: OrderUtxo,
    pub taker_in: OutputUtxo,
    pub source_output: OutputUtxo,
    pub destination_output: OutputUtxo,
    pub external_data_hash: [u8; 32],
}

impl TakeProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<TakeProofInputs> {
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
        if self.destination_output.blinding != self.escrow.derived_destination_blinding()? {
            bail!("destination output blinding does not match the derived blinding");
        }
        if terms.take_mode != TAKE_MODE_DERIVED {
            bail!("order take_mode does not authorize the derived take");
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
        let public_input_hash = TakePublicInput {
            private_tx_hash: &private_tx_hash,
            expiry: terms.expiry,
        }
        .hash()
        .map_err(err)?;
        Ok(TakeProofInputs {
            public_input_hash,
            private_tx_hash,
            order,
            escrow,
            taker_in,
            source_output,
            destination_output,
            external_data_hash: self.external_data_hash,
        })
    }
}
