use anyhow::{bail, Result};
use dynamic_swap_program::instructions::create_escrow::EscrowOpenPublicInput;
use dynamic_swap_prover::{EscrowOpenProofInputs, ProofInputUtxo};
use zolana_keypair::hash::owner_hash;
use zolana_transaction::instructions::{
    transact::{spp_proof_inputs::asset_field, PrivateTxHash, SppProofOutputUtxo},
    types::SppProofInputUtxo,
};

use crate::{err, shared::check_output_utxo};

/// Proof-input params for the `escrow_open` circuit (`create_escrow`): 2-in
/// (taker source UTXO, maker funding UTXO) / 3-out (escrow order UTXO,
/// reservation UTXO, maker change UTXO), the exact IN2_OUT3 shape, no padding.
/// No taker change output: `source_in` must match `order_amount` exactly --
/// `create_escrow`'s instruction data already sits at Solana's whole-transaction
/// size limit with a Groth16 proof, SPP's own embedded proof, and 3 real
/// confidential outputs, so a 4th output doesn't fit. `order_amount` is the one
/// private witness shared across the order UTXO's amount, the reservation's
/// worst-case size, and the maker-change decrement.
pub struct EscrowOpenProofInputParams {
    pub source_in: SppProofInputUtxo,
    pub maker_funding: SppProofInputUtxo,
    pub order_out: SppProofOutputUtxo,
    pub reservation_out: SppProofOutputUtxo,
    pub maker_change: SppProofOutputUtxo,
    pub max_price: u64,
    /// The escrow_authority PDA's owner-hash (from
    /// `EscrowUtxo::order_utxo_owner_hash`); the program recomputes and binds
    /// the same value to `OrderOut.Owner`.
    pub escrow_authority_owner_hash: [u8; 32],
    /// The pair's source-asset commitment (`Pair.source_asset` =
    /// `asset_field(source_mint)`); bound to `SourceIn.Asset`.
    pub source_asset: [u8; 32],
    /// The pair's destination-asset commitment (`Pair.destination_asset`);
    /// bound to `MakerFunding.Asset`.
    pub destination_asset: [u8; 32],
    /// A near-future estimate of `Clock::get()?.slot` at execution time --
    /// the program only tolerance-checks this against the real current slot
    /// rather than requiring an exact match; see `EscrowTerms`'s doc and
    /// `CREATED_AT_SLOT_TOLERANCE`.
    pub created_at: u64,
    pub order_amount: u64,
    pub external_data_hash: [u8; 32],
}

impl EscrowOpenProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<EscrowOpenProofInputs> {
        let source_in = ProofInputUtxo::try_from(&self.source_in).map_err(err)?;
        let maker_funding = ProofInputUtxo::try_from(&self.maker_funding).map_err(err)?;
        let order_out = ProofInputUtxo::try_from(&self.order_out).map_err(err)?;
        let reservation_out = ProofInputUtxo::try_from(&self.reservation_out).map_err(err)?;
        let maker_change = ProofInputUtxo::try_from(&self.maker_change).map_err(err)?;

        if self.source_in.utxo.amount != self.order_amount {
            bail!("source_in amount does not match order_amount (no change output supported)");
        }
        if asset_field(&self.source_in.utxo.asset).map_err(err)? != self.source_asset {
            bail!("source_in asset does not match the pair source asset");
        }
        if asset_field(&self.maker_funding.utxo.asset).map_err(err)? != self.destination_asset {
            bail!("maker_funding asset does not match the pair destination asset");
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
        if self.reservation_out.asset != self.maker_funding.utxo.asset {
            bail!("reservation output asset does not match the maker funding asset");
        }
        let reserved = self
            .order_amount
            .checked_mul(self.max_price)
            .ok_or_else(|| err("order_amount * max_price overflows"))?;
        if self.reservation_out.amount != reserved {
            bail!("reservation output amount does not match order_amount * max_price");
        }
        let expected_change = self
            .maker_funding
            .utxo
            .amount
            .checked_sub(reserved)
            .ok_or_else(|| err("reservation exceeds the maker funding amount"))?;
        check_output_utxo(
            "maker_change",
            &self.maker_change,
            &self.maker_funding.utxo.asset,
            expected_change,
        )?;
        let order_out_hash = order_out.hash().map_err(err)?;
        if self.reservation_out.data_hash != Some(order_out_hash) {
            bail!("reservation output data_hash does not commit to the order output's own hash");
        }

        // The real shape is 2-in/3-out, exactly the supported IN2_OUT3 shape --
        // no padding. Output order (order, reservation, maker_change) must match
        // the circuit's `privateTxHashInputs` and the program's output indices.
        let private_tx_hash = PrivateTxHash::new(
            &[
                source_in.hash().map_err(err)?,
                maker_funding.hash().map_err(err)?,
            ],
            &[
                order_out_hash,
                reservation_out.hash().map_err(err)?,
                maker_change.hash().map_err(err)?,
            ],
            &self.external_data_hash,
        )
        .hash()
        .map_err(err)?;

        let public_input_hash = EscrowOpenPublicInput {
            private_tx_hash: &private_tx_hash,
            created_at: self.created_at,
            escrow_authority_owner_hash: &self.escrow_authority_owner_hash,
            source_asset: &self.source_asset,
            destination_asset: &self.destination_asset,
        }
        .hash()
        .map_err(err)?;

        Ok(EscrowOpenProofInputs {
            public_input_hash,
            private_tx_hash,
            max_price: self.max_price,
            created_at: self.created_at,
            escrow_authority_owner_hash: self.escrow_authority_owner_hash,
            source_asset: self.source_asset,
            destination_asset: self.destination_asset,
            order_amount: self.order_amount,
            source_in,
            maker_funding,
            order_out,
            reservation_out,
            maker_change,
            external_data_hash: self.external_data_hash,
        })
    }
}
