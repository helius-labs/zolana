use anyhow::{bail, Result};
use swap_program::instructions::cancel::CancelPublicInput;
use swap_prover::{CancelProofInputs, OrderTermsProofInput};
use zolana_keypair::P256Pubkey;
use zolana_transaction::{
    instructions::transact::{PrivateTxHash, SppProofOutputUtxo},
    ProofInputUtxo,
};

use crate::{err, shared::check_output_utxo, state::OrderUtxo};

pub struct CancelProofInputParams {
    pub order_utxo: OrderUtxo,
    pub taker_viewing_pubkey: P256Pubkey,
    pub source_output: SppProofOutputUtxo,
    pub external_data_hash: [u8; 32],
}

impl CancelProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<CancelProofInputs> {
        let terms = &self.order_utxo.terms;
        let maker = check_output_utxo(
            "source_output",
            &self.source_output,
            &self.order_utxo.source_mint,
            self.order_utxo.source_amount,
        )?;
        if maker != terms.destination {
            bail!("source output owner does not match the order destination");
        }
        let order = OrderTermsProofInput::try_from(terms)?;
        let maker_owner_pk_field = maker.signing_pubkey.owner_pk_field().map_err(err)?;
        let order_utxo =
            ProofInputUtxo::try_from(&self.order_utxo.to_input_utxo()?).map_err(err)?;
        let source_output = ProofInputUtxo::try_from(&self.source_output).map_err(err)?;
        let private_tx_hash = PrivateTxHash::new(
            &[order_utxo.hash().map_err(err)?],
            &[source_output.hash().map_err(err)?],
            &self.external_data_hash,
        )
        .hash()
        .map_err(err)?;
        let public_input_hash = CancelPublicInput {
            private_tx_hash: &private_tx_hash,
            expiry: terms.expiry,
            maker_owner_pk_field: &maker_owner_pk_field,
        }
        .hash()
        .map_err(err)?;
        Ok(CancelProofInputs {
            public_input_hash,
            private_tx_hash,
            order,
            maker_owner_pk_field,
            maker_nullifier_pk: maker.nullifier_pubkey,
            order_utxo,
            source_output,
            external_data_hash: self.external_data_hash,
        })
    }
}
