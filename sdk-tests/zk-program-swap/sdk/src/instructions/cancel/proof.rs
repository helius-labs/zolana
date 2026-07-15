use anyhow::{bail, Result};
use swap_program::instructions::cancel::CancelPublicInput;
use swap_prover::CancelProofInputs;
use zolana_keypair::P256Pubkey;
use zolana_transaction::{
    instructions::transact::{OutputUtxo, PrivateTxHash},
    ProofInputUtxo,
};

use crate::{
    err,
    order::{ensure_payout, OrderUtxo},
};

pub struct CancelProofInputParams {
    pub escrow: OrderUtxo,
    pub taker_viewing_pubkey: P256Pubkey,
    pub source_output: OutputUtxo,
    pub external_data_hash: [u8; 32],
}

impl CancelProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<CancelProofInputs> {
        let terms = &self.escrow.terms;
        let maker = ensure_payout(
            "source_output",
            &self.source_output,
            &self.escrow.source_mint,
            self.escrow.source_amount,
        )?;
        if maker != terms.destination {
            bail!("source output owner does not match the order destination");
        }
        let order = terms.field_elements()?;
        let maker_owner_pk_field = maker.signing_pubkey.owner_pk_field().map_err(err)?;
        let escrow = ProofInputUtxo::try_from(&self.escrow.to_input_utxo()?).map_err(err)?;
        let source_output = ProofInputUtxo::try_from(&self.source_output).map_err(err)?;
        let private_tx_hash = PrivateTxHash::new(
            &[escrow.hash().map_err(err)?],
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
            escrow,
            source_output,
            external_data_hash: self.external_data_hash,
        })
    }
}
