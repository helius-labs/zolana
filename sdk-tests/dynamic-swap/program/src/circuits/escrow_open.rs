use spr_program::{
    circuit::PublicInputs, input, poseidon, require, require_eq, CircuitError, Field, ZkProgram,
};

use super::{
    shared::{check_private_tx_hash, require_some, require_u64},
    Commitment, ProofInputUtxo,
};

#[input]
#[derive(ZkProgram)]
#[zk_program(raw_client)]
pub struct EscrowOpen {
    pub private: EscrowOpenPrivateInputs,
    pub public: EscrowOpenPublicInputs,
}

#[input]
pub struct EscrowOpenPrivateInputs {
    pub private_tx_hash: Field,
    pub order_amount: u64,
    pub min_price: u64,
    pub source_in: ProofInputUtxo,
    pub order_out: ProofInputUtxo,
    pub taker_change: ProofInputUtxo,
    pub private_tx_blinding: Field,
}

#[input]
#[derive(PublicInputs)]
pub struct EscrowOpenPublicInputs {
    pub escrow_authority_owner_hash: Field,
    pub source_asset: Field,
    pub public_price_floor: u64,
    pub price_tolerance: u64,
    pub min_order_amount: u64,
    pub max_order_size: u64,
}

impl EscrowOpen {
    pub fn execute(&self) -> Result<Commitment, CircuitError> {
        let private = &self.private;
        let public = &self.public;
        require(public.min_order_amount <= private.order_amount);
        let reference_price = require_some(
            public
                .public_price_floor
                .checked_add(public.price_tolerance),
        );
        let coverage_price = require_some(reference_price.checked_add(public.price_tolerance));
        // The minimum price lies inside the public quote window.
        require(public.public_price_floor <= private.min_price);
        require(private.min_price <= reference_price);
        // The covered payout fits the reserved liquidity.
        let covered = require_some(private.order_amount.checked_mul(coverage_price));
        require(covered <= public.max_order_size);

        let source = &private.source_in;
        let order = &private.order_out;
        let change = &private.taker_change;
        let order_amount = Field::from(private.order_amount);
        source.assert_default_ring();
        require_eq(source.data_hash, Field::zero());
        require_eq(source.asset, public.source_asset);

        order.assert_default_ring();
        require_eq(order.owner_hash, public.escrow_authority_owner_hash);
        require_eq(order.asset, source.asset);
        require_eq(order.amount, order_amount);
        // The order commits to the recipient and the minimum price.
        require_eq(
            order.data_hash,
            poseidon(&[source.owner_hash, Field::from(private.min_price)])?,
        );

        change.assert_default_ring();
        require_eq(change.data_hash, Field::zero());
        require_eq(change.asset, source.asset);
        require_eq(change.owner_hash, source.owner_hash);
        // The change conserves the source amount, which covers the order.
        require_eq(change.amount, source.amount - order_amount);
        require_u64(change.amount);

        check_private_tx_hash(
            &[source.hash()?],
            &[order.hash()?, change.hash()?],
            private.private_tx_blinding,
            private.private_tx_hash,
        )?;
        Ok(Commitment(public.hash(&private.private_tx_hash)?))
    }
}
