use anyhow::{bail, Result};
use dynamic_swap_program::instructions::create_escrow::EscrowOpenPublicInput;
use dynamic_swap_prover::{EscrowOpenProofInputs, ProofInputUtxo};
use zolana_keypair::hash::owner_hash;
use zolana_transaction::instructions::{
    transact::{spp_proof_inputs::asset_field, PrivateTxHash, SppProofOutputUtxo},
    types::SppProofInputUtxo,
};

use crate::{err, shared::check_output_utxo, state::order_data_hash};

fn validate_order_terms(
    public_price_floor: u64,
    price_tolerance: u64,
    min_order_amount: u64,
    order_amount: u64,
    min_price: u64,
    max_order_size: u64,
) -> Result<()> {
    if price_tolerance == 0 {
        bail!("price_tolerance must be nonzero");
    }
    if min_order_amount == 0 || order_amount < min_order_amount {
        bail!("order_amount is below the pair's min_order_amount");
    }
    let reference_price = public_price_floor
        .checked_add(price_tolerance)
        .ok_or_else(|| err("public_price_floor + price_tolerance overflows"))?;
    let coverage_price = reference_price
        .checked_add(price_tolerance)
        .ok_or_else(|| err("public price coverage overflows"))?;
    if min_price < public_price_floor || min_price > reference_price {
        bail!("min_price is outside the private range allowed by the public floor");
    }
    let worst_case_owed = order_amount
        .checked_mul(coverage_price)
        .ok_or_else(|| err("order_amount * coverage_price overflows"))?;
    if worst_case_owed > max_order_size {
        bail!("owed exceeds the pair's max_order_size");
    }
    Ok(())
}

/// Proof-input params for the `escrow_open` circuit (`create_escrow`): 1-in
/// (taker source UTXO) / 2-out (escrow order UTXO, taker change UTXO), the
/// exact IN1_OUT2 shape, no padding. Taker-only: the maker's committed
/// liquidity is reserved program-side and spent at settle time. The circuit
/// enforces the private order policy and caps the worst-case payout at the
/// public price window's coverage edge. The live price is not proof-bound.
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
    pub public_price_floor: u64,
    pub price_tolerance: u64,
    pub min_order_amount: u64,
    /// The pair's immutable `max_order_size`; caps owed in-circuit.
    pub max_order_size: u64,
    pub order_amount: u64,
    pub min_price: u64,
    pub external_data_hash: [u8; 32],
}

impl EscrowOpenProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<EscrowOpenProofInputs> {
        let source_in = ProofInputUtxo::try_from(&self.source_in).map_err(err)?;
        let order_out = ProofInputUtxo::try_from(&self.order_out).map_err(err)?;
        let taker_change = ProofInputUtxo::try_from(&self.taker_change).map_err(err)?;

        validate_order_terms(
            self.public_price_floor,
            self.price_tolerance,
            self.min_order_amount,
            self.order_amount,
            self.min_price,
            self.max_order_size,
        )?;
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
        // The circuit binds the recipient half of the order's composite
        // DataHash to the source UTXO's owner: the payout goes back to the
        // taker whose funds are escrowed.
        let expected_order_data_hash = order_data_hash(&source_in.owner_hash, self.min_price)?;
        if self.order_out.data_hash != Some(expected_order_data_hash) {
            bail!("order output data_hash does not commit the recipient and private min_price");
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
            public_price_floor: self.public_price_floor,
            price_tolerance: self.price_tolerance,
            min_order_amount: self.min_order_amount,
            max_order_size: self.max_order_size,
        }
        .hash()
        .map_err(err)?;

        Ok(EscrowOpenProofInputs {
            public_input_hash,
            private_tx_hash,
            escrow_authority_owner_hash: self.escrow_authority_owner_hash,
            source_asset: self.source_asset,
            public_price_floor: self.public_price_floor,
            price_tolerance: self.price_tolerance,
            min_order_amount: self.min_order_amount,
            max_order_size: self.max_order_size,
            order_amount: self.order_amount,
            min_price: self.min_price,
            source_in,
            order_out,
            taker_change,
            external_data_hash: self.external_data_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::validate_order_terms;

    #[test]
    fn validates_private_limit_and_worst_case_coverage() {
        assert!(validate_order_terms(4, 1, 10, 10, 4, 60).is_ok());
        assert!(validate_order_terms(4, 1, 10, 10, 5, 60).is_ok());
        assert!(validate_order_terms(4, 1, 10, 9, 4, 60).is_err());
        assert!(validate_order_terms(4, 1, 10, 10, 3, 60).is_err());
        assert!(validate_order_terms(4, 1, 10, 10, 6, 60).is_err());
        assert!(validate_order_terms(4, 1, 10, 11, 5, 60).is_err());
    }

    #[test]
    fn rejects_zero_tolerance_and_checked_arithmetic_overflow() {
        assert!(validate_order_terms(4, 0, 1, 1, 4, 4).is_err());
        assert!(validate_order_terms(u64::MAX, 1, 1, 1, u64::MAX, u64::MAX).is_err());
        assert!(validate_order_terms(0, 1, 1, u64::MAX, 1, u64::MAX).is_err());
    }
}
