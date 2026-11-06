use spr_program::{
    circuit::PublicInputs, input, poseidon, require, require_eq, CircuitError, Field, ZkProgram,
};

use super::{
    shared::{
        check_private_tx_hash, check_transaction_blindings, order_blinding_seed, require_some,
        require_u64, SETTLE_BLINDING_DOMAIN,
    },
    Commitment, ProofInputUtxo,
};

#[input]
#[derive(ZkProgram)]
#[zk_program(raw_client)]
pub struct PoolSettle {
    pub private: PoolSettlePrivateInputs,
    pub public: PoolSettlePublicInputs,
}

#[input]
pub struct PoolSettlePrivateInputs {
    pub private_tx_hash: Field,
    pub order_amount: u64,
    pub recipient_owner_hash: Field,
    pub min_price: u64,
    pub order_in: ProofInputUtxo,
    pub pool_in: ProofInputUtxo,
    pub recipient_out: ProofInputUtxo,
    pub pool_change: ProofInputUtxo,
    pub maker_receipt: ProofInputUtxo,
    pub private_tx_blinding: Field,
}

#[input]
#[derive(PublicInputs)]
pub struct PoolSettlePublicInputs {
    pub execution_price: u64,
    pub order_in_hash: Field,
    pub destination_asset: Field,
    pub pool_authority_owner_hash: Field,
    pub max_order_size: u64,
    pub receipt_owner_hash: Field,
    pub first_nullifier: Field,
}

impl PoolSettle {
    pub fn execute(&self) -> Result<Commitment, CircuitError> {
        let private = &self.private;
        let public = &self.public;
        let order = &private.order_in;
        let pool = &private.pool_in;
        let recipient = &private.recipient_out;
        let change = &private.pool_change;
        let receipt = &private.maker_receipt;
        let order_amount = Field::from(private.order_amount);

        order.assert_default_ring();
        require_eq(order.amount, order_amount);
        // The opening keeps the order's recipient and minimum price.
        require_eq(
            order.data_hash,
            poseidon(&[private.recipient_owner_hash, Field::from(private.min_price)])?,
        );
        let order_hash = order.hash()?;
        require_eq(order_hash, public.order_in_hash);
        // The payout comes from program-locked pool liquidity.
        pool.assert_default_ring();
        require_eq(pool.owner_hash, public.pool_authority_owner_hash);
        require_eq(pool.asset, public.destination_asset);
        require_u64(pool.data_hash);

        let blinding_seed = order_blinding_seed(SETTLE_BLINDING_DOMAIN, order.blinding)?;
        check_transaction_blindings(
            public.first_nullifier,
            blinding_seed,
            private.private_tx_blinding,
            &[recipient.blinding, change.blinding, receipt.blinding],
        )?;

        require(public.execution_price != 0);
        let owed = Field::from(require_some(
            private.order_amount.checked_mul(public.execution_price),
        ));
        let fills = private.min_price <= public.execution_price;
        let settled_owed = if fills { owed } else { Field::zero() };

        // A fill pays the destination asset, otherwise the order is refunded.
        recipient.assert_default_ring();
        require_eq(recipient.data_hash, Field::zero());
        require_eq(
            recipient.asset,
            if fills { pool.asset } else { order.asset },
        );
        require_eq(recipient.amount, if fills { owed } else { order_amount });
        require_eq(recipient.owner_hash, private.recipient_owner_hash);

        // The pool funds the payout and stays locked to the pool authority.
        change.assert_default_ring();
        require_eq(change.owner_hash, public.pool_authority_owner_hash);
        require_eq(change.asset, pool.asset);
        require_eq(change.amount, pool.amount - settled_owed);
        require_u64(change.amount);
        // The order's reservation leaves `booked` in full, so the pool's booked
        // total drops by exactly what closing the reservation releases.
        require_eq(
            change.data_hash,
            pool.data_hash - Field::from(public.max_order_size),
        );
        require_u64(change.data_hash);

        receipt.assert_default_ring();
        require_eq(receipt.data_hash, Field::zero());
        require_eq(receipt.asset, order.asset);
        require_eq(
            receipt.amount,
            if fills { order_amount } else { Field::zero() },
        );
        require_eq(receipt.owner_hash, public.receipt_owner_hash);

        check_private_tx_hash(
            &[order_hash, pool.hash()?],
            &[recipient.hash()?, change.hash()?, receipt.hash()?],
            private.private_tx_blinding,
            private.private_tx_hash,
        )?;
        Ok(Commitment(public.hash(&private.private_tx_hash)?))
    }
}
