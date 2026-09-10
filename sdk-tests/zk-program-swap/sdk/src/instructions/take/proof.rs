use anyhow::{bail, Result};
use swap_program::instructions::take::TakePublicInput;
use swap_prover::{OrderTermsProofInput, TakeProofInputs, TAKE_MODE_DERIVED};
use zolana_transaction::{
    instructions::transact::{PrivateTxHash, SppProofOutputUtxo},
    utxo::{
        derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
    },
    ProofInputUtxo,
};

use super::take_blinding_seed;
use crate::{err, shared::check_output_utxo, state::OrderUtxo};

pub struct TakeProofInputParams {
    pub order_utxo: OrderUtxo,
    pub taker_in: SppProofOutputUtxo,
    pub source_output: SppProofOutputUtxo,
    pub destination_output: SppProofOutputUtxo,
    pub external_data_hash: [u8; 32],
    /// `SppProofInputs::private_tx_blinding()`, the fifth `private_tx_hash`
    /// preimage element.
    pub private_tx_blinding: [u8; 32],
    /// Raw id of the tree the order and taker UTXOs are spent from.
    pub input_tree_id: u16,
    /// Raw id of the tree the source and destination outputs are appended to.
    pub output_tree_id: u16,
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
        if terms.take_mode != TAKE_MODE_DERIVED {
            bail!("order take_mode does not authorize the derived take");
        }
        let order = OrderTermsProofInput::try_from(terms)?;
        let order_input = self.order_utxo.to_input_utxo()?.in_tree(self.input_tree_id);
        let first_nullifier = order_input.nullifier().map_err(err)?;
        let blinding_seed = take_blinding_seed(&self.order_utxo.blinding)?;
        let seed = derive_output_blinding_seed(&first_nullifier, &blinding_seed).map_err(err)?;
        if self.private_tx_blinding
            != derive_private_tx_blinding(&first_nullifier, &blinding_seed).map_err(err)?
        {
            bail!("take blinding seed must derive from the order opening");
        }
        for (index, output) in [&self.source_output, &self.destination_output]
            .into_iter()
            .enumerate()
        {
            if output.blinding
                != derive_transact_output_blinding(&first_nullifier, &seed, index as u32)
                    .map_err(err)?
            {
                bail!("take output {index} blinding must derive from the order opening");
            }
        }
        let order_utxo = ProofInputUtxo::try_from(&order_input).map_err(err)?;
        let taker_in =
            ProofInputUtxo::try_from((&self.taker_in, self.input_tree_id)).map_err(err)?;
        let source_output =
            ProofInputUtxo::try_from((&self.source_output, self.output_tree_id)).map_err(err)?;
        let destination_output =
            ProofInputUtxo::try_from((&self.destination_output, self.output_tree_id))
                .map_err(err)?;
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
            &self.private_tx_blinding,
        )
        .hash()
        .map_err(err)?;
        let public_input_hash = TakePublicInput {
            private_tx_hash: &private_tx_hash,
            expiry: terms.expiry,
            first_nullifier: &first_nullifier,
        }
        .hash()
        .map_err(err)?;
        Ok(TakeProofInputs {
            public_input_hash,
            private_tx_hash,
            first_nullifier,
            order,
            order_utxo,
            taker_in,
            source_output,
            destination_output,
            external_data_hash: self.external_data_hash,
            private_tx_blinding: self.private_tx_blinding,
        })
    }
}
