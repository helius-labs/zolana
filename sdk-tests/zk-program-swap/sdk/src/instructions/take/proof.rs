use anyhow::{bail, Result};
use swap_program::instructions::{shared::u64_right_align, take::TakePublicInput};
use swap_prover::{
    OrderTermsProofInput, TakeProofInputs, DESTINATION_BLINDING_DOMAIN, TAKE_MODE_DERIVED,
};
use zolana_keypair::{constants::BLINDING_LEN, hash::poseidon};
use zolana_transaction::{
    instructions::transact::{PrivateTxHash, SppProofOutputUtxo},
    utxo::Blinding,
    ProofInputUtxo,
};

use crate::{
    err,
    shared::{check_output_utxo, right_align_blinding},
    state::OrderUtxo,
};

pub fn derive_destination_blinding(order_utxo_blinding: &Blinding) -> Result<Blinding> {
    let domain = u64_right_align(DESTINATION_BLINDING_DOMAIN);
    let derived = poseidon(&[&right_align_blinding(order_utxo_blinding), &domain]).map_err(err)?;
    let mut blinding = [0u8; BLINDING_LEN];
    blinding.copy_from_slice(derived.get(1..32).ok_or_else(|| err("blinding tail"))?);
    Ok(blinding)
}

pub struct TakeProofInputParams {
    pub order_utxo: OrderUtxo,
    pub taker_in: SppProofOutputUtxo,
    pub source_output: SppProofOutputUtxo,
    pub destination_output: SppProofOutputUtxo,
    pub external_data_hash: [u8; 32],
}

impl TakeProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<TakeProofInputs> {
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
        if self.destination_output.blinding != self.order_utxo.derived_destination_blinding()? {
            bail!("destination output blinding does not match the derived blinding");
        }
        if terms.take_mode != TAKE_MODE_DERIVED {
            bail!("order take_mode does not authorize the derived take");
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
            order_utxo,
            taker_in,
            source_output,
            destination_output,
            external_data_hash: self.external_data_hash,
        })
    }
}
