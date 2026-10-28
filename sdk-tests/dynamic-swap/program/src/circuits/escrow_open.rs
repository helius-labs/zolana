use zolana_program::{
    circuit::{zero, Assert, Circuit, PublicInputs, U64},
    conversion::ProofInput,
    CircuitError, ZkProgramCircuit,
};

use super::{shared::check_private_tx_hash, Commitment, ProofInputUtxo};

#[derive(Clone, Debug, ZkProgramCircuit)]
pub struct EscrowOpen {
    pub private: EscrowOpenPrivateInputs,
    pub public: EscrowOpenPublicInputs,
}

#[derive(Clone, Debug, ProofInput)]
pub struct EscrowOpenPrivateInputs {
    pub private_tx_hash: [u8; 32],
    pub order_amount: u64,
    pub min_price: u64,
    pub source_in: ProofInputUtxo,
    pub order_out: ProofInputUtxo,
    pub taker_change: ProofInputUtxo,
    pub private_tx_blinding: [u8; 32],
}

#[derive(Clone, Debug, PublicInputs)]
pub struct EscrowOpenPublicInputs {
    pub escrow_authority_owner_hash: [u8; 32],
    pub source_asset: [u8; 32],
    pub public_price_floor: u64,
    pub price_tolerance: u64,
    pub min_order_amount: u64,
    pub max_order_size: u64,
}

impl Circuit for EscrowOpenCircuit {
    type Output = Commitment;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let private = &self.private;
        let public = &self.public;
        public.min_order_amount.assert_less_or_equal(
            &private.order_amount,
            "the order is smaller than the pair minimum",
        )?;
        let reference_price = public
            .public_price_floor
            .checked_add(&public.price_tolerance, "the reference price overflows u64")?;
        let coverage_price = reference_price
            .checked_add(&public.price_tolerance, "the coverage price overflows u64")?;
        private.min_price.assert_in_range(
            &public.public_price_floor,
            &reference_price,
            "the minimum price is outside the public quote window",
        )?;
        private
            .order_amount
            .checked_mul(&coverage_price, "the covered payout overflows u64")?
            .assert_less_or_equal(
                &public.max_order_size,
                "the covered payout exceeds the reserved liquidity",
            )?;

        let source = &private.source_in;
        let order = &private.order_out;
        let change = &private.taker_change;
        source.assert_default_ring()?;
        source
            .data_hash
            .assert_equal(&zero(), "the source is not a token note")?;
        source
            .asset
            .assert_equal(&public.source_asset, "the source asset is not the pair's")?;

        order.assert_default_ring()?;
        order.owner_hash.assert_equal(
            &public.escrow_authority_owner_hash,
            "the order is not owned by the escrow authority",
        )?;
        order
            .asset
            .assert_equal(&source.asset, "the order changes the escrowed asset")?;
        order.amount.assert_equal(
            &private.order_amount.var(),
            "the order amount differs from the escrowed amount",
        )?;
        order.data_hash.assert_equal(
            &zolana_program::circuit::poseidon(&[
                source.owner_hash.clone(),
                private.min_price.var(),
            ])?,
            "the order does not commit to the recipient and minimum price",
        )?;

        change.assert_default_ring()?;
        change
            .data_hash
            .assert_equal(&zero(), "the taker change is not a token note")?;
        change
            .asset
            .assert_equal(&source.asset, "the taker change changes the asset")?;
        change.owner_hash.assert_equal(
            &source.owner_hash,
            "the taker change belongs to another owner",
        )?;
        change.amount.assert_equal(
            &source.amount.minus(&private.order_amount.var()),
            "the taker change does not conserve the source amount",
        )?;
        let _ = U64::from_var(&change.amount, "the order exceeds the source amount")?;

        check_private_tx_hash(
            &[source.hash()?],
            &[order.hash()?, change.hash()?],
            &private.private_tx_blinding,
            &private.private_tx_hash,
        )?;
        Ok(Commitment(public.hash(&private.private_tx_hash)?))
    }
}
