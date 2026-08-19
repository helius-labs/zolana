use anyhow::{bail, Result};
use dynamic_swap_program::instructions::create_escrow::EscrowOpenPublicInput;
use dynamic_swap_prover::{EscrowOpenProofInputs, ProofInputUtxo};
use zolana_keypair::hash::owner_hash;
use zolana_transaction::instructions::{
    transact::{spp_proof_inputs::asset_field, PrivateTxHash, SppProofOutputUtxo},
    types::SppProofInputUtxo,
};

use crate::{err, shared::check_output_utxo};

/// Proof-input params for the `escrow_open` circuit (`create_escrow`): 1-in
/// (taker source UTXO) / 2-out (escrow order UTXO, taker change UTXO), the
/// exact IN1_OUT2 shape, no padding. Taker-only: the maker's liquidity enters
/// at settle time. `max_price` never appears here -- it is instruction data the
/// program checks against the pair price and discards.
pub struct EscrowOpenProofInputParams {
    pub source_in: SppProofInputUtxo,
    pub order_out: SppProofOutputUtxo,
    pub taker_change: SppProofOutputUtxo,
    /// The escrow_authority PDA's owner-hash (see
    /// `state::escrow_authority_address`); the program recomputes and binds the
    /// same value to `OrderOut.Owner`.
    pub escrow_authority_owner_hash: [u8; 32],
    /// The pair's source-asset commitment (`Pair.source_asset` =
    /// `asset_field(source_mint)`); bound to `SourceIn.Asset`.
    pub source_asset: [u8; 32],
    pub order_amount: u64,
    pub external_data_hash: [u8; 32],
}

impl EscrowOpenProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<EscrowOpenProofInputs> {
        let source_in = ProofInputUtxo::try_from(&self.source_in).map_err(err)?;
        let order_out = ProofInputUtxo::try_from(&self.order_out).map_err(err)?;
        let taker_change = ProofInputUtxo::try_from(&self.taker_change).map_err(err)?;

        if self.order_amount == 0 {
            bail!("order_amount must be nonzero");
        }
        if asset_field(&self.source_in.utxo.asset).map_err(err)? != self.source_asset {
            bail!("source_in asset does not match the pair source asset");
        }
        let order_owner = self
            .order_out
            .owner_address
            .ok_or_else(|| err("order_out owner address missing"))?;
        if owner_hash(&order_owner.signing_pubkey, &order_owner.nullifier_pubkey).map_err(err)?
            != self.escrow_authority_owner_hash
        {
            bail!("order_out owner is not the escrow_authority owner-hash");
        }
        if self.order_out.amount != self.order_amount {
            bail!("order output amount does not match order_amount");
        }
        // The circuit binds the recipient (the order's DataHash) to the source
        // UTXO's owner: the payout goes back to the taker whose funds are
        // escrowed.
        if self.order_out.data_hash != Some(source_in.owner_hash) {
            bail!("order output data_hash does not commit the source owner as recipient");
        }
        let expected_change = self
            .source_in
            .utxo
            .amount
            .checked_sub(self.order_amount)
            .ok_or_else(|| err("order_amount exceeds the source amount"))?;
        let change_owner = check_output_utxo(
            "taker_change",
            &self.taker_change,
            &self.source_in.utxo.asset,
            expected_change,
        )?;
        if change_owner.owner_hash().map_err(err)? != source_in.owner_hash {
            bail!("taker_change owner does not match the source owner");
        }

        // The real shape is 1-in/2-out, exactly the supported IN1_OUT2 shape --
        // no padding. Output order (order, taker_change) must match the
        // circuit's `privateTxHashInputs` and the program's output index.
        let private_tx_hash = PrivateTxHash::new(
            &[source_in.hash().map_err(err)?],
            &[
                order_out.hash().map_err(err)?,
                taker_change.hash().map_err(err)?,
            ],
            &self.external_data_hash,
        )
        .hash()
        .map_err(err)?;

        let public_input_hash = EscrowOpenPublicInput {
            private_tx_hash: &private_tx_hash,
            escrow_authority_owner_hash: &self.escrow_authority_owner_hash,
            source_asset: &self.source_asset,
        }
        .hash()
        .map_err(err)?;

        Ok(EscrowOpenProofInputs {
            public_input_hash,
            private_tx_hash,
            escrow_authority_owner_hash: self.escrow_authority_owner_hash,
            source_asset: self.source_asset,
            order_amount: self.order_amount,
            source_in,
            order_out,
            taker_change,
            external_data_hash: self.external_data_hash,
        })
    }
}
