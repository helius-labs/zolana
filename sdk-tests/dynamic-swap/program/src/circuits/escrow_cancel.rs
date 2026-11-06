use spr_program::{
    circuit::PublicInputs, input, poseidon, require_eq, CircuitError, Field, ZkProgram,
};

use super::{
    shared::{
        check_private_tx_hash, check_transaction_blindings, order_blinding_seed,
        CANCEL_BLINDING_DOMAIN,
    },
    Commitment, ProofInputUtxo,
};

#[input]
#[derive(ZkProgram)]
#[zk_program(raw_client)]
pub struct EscrowCancel {
    pub private: EscrowCancelPrivateInputs,
    pub public: EscrowCancelPublicInputs,
}

#[input]
pub struct EscrowCancelPrivateInputs {
    pub private_tx_hash: Field,
    pub order_amount: u64,
    pub recipient_owner_hash: Field,
    pub min_price: u64,
    pub order_in: ProofInputUtxo,
    pub refund_out: ProofInputUtxo,
    pub private_tx_blinding: Field,
}

#[input]
#[derive(PublicInputs)]
pub struct EscrowCancelPublicInputs {
    pub order_in_hash: Field,
    pub first_nullifier: Field,
}

impl EscrowCancel {
    pub fn execute(&self) -> Result<Commitment, CircuitError> {
        let private = &self.private;
        let public = &self.public;
        let order = &private.order_in;
        let refund = &private.refund_out;
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

        // The refund returns the full order, in its source asset, to its
        // recipient.
        refund.assert_default_ring();
        require_eq(refund.data_hash, Field::zero());
        require_eq(refund.asset, order.asset);
        require_eq(refund.amount, order_amount);
        require_eq(refund.owner_hash, private.recipient_owner_hash);

        let blinding_seed = order_blinding_seed(CANCEL_BLINDING_DOMAIN, order.blinding)?;
        check_transaction_blindings(
            public.first_nullifier,
            blinding_seed,
            private.private_tx_blinding,
            &[refund.blinding],
        )?;
        check_private_tx_hash(
            &[order_hash],
            &[refund.hash()?],
            private.private_tx_blinding,
            private.private_tx_hash,
        )?;
        Ok(Commitment(public.hash(&private.private_tx_hash)?))
    }
}
