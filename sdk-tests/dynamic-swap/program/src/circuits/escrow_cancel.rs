use zolana_program::{
    circuit::{constant, poseidon, zero, Assert, Circuit, PublicInputs},
    conversion::ProofInput,
    CircuitError, ZkProgramCircuit,
};

use super::{
    shared::{check_private_tx_hash, check_transaction_blindings},
    Commitment, ProofInputUtxo,
};

#[derive(Clone, Debug, ZkProgramCircuit)]
pub struct EscrowCancel {
    pub private: EscrowCancelPrivateInputs,
    pub public: EscrowCancelPublicInputs,
}

#[derive(Clone, Debug, ProofInput)]
pub struct EscrowCancelPrivateInputs {
    pub private_tx_hash: [u8; 32],
    pub order_amount: u64,
    pub recipient_owner_hash: [u8; 32],
    pub min_price: u64,
    pub order_in: ProofInputUtxo,
    pub refund_out: ProofInputUtxo,
    pub private_tx_blinding: [u8; 32],
}

#[derive(Clone, Debug, PublicInputs)]
pub struct EscrowCancelPublicInputs {
    pub order_in_hash: [u8; 32],
    pub first_nullifier: [u8; 32],
}

impl Circuit for EscrowCancelCircuit {
    type Output = Commitment;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let private = &self.private;
        let public = &self.public;
        let order = &private.order_in;
        let refund = &private.refund_out;
        order.assert_default_ring()?;
        order.amount.assert_equal(
            &private.order_amount.var(),
            "the order opening has another amount",
        )?;
        order.data_hash.assert_equal(
            &poseidon(&[
                private.recipient_owner_hash.clone(),
                private.min_price.var(),
            ])?,
            "the order opening changes the recipient or minimum price",
        )?;
        let order_hash = order.hash()?;
        order_hash.assert_equal(
            &public.order_in_hash,
            "the refunded order is not the escrow's order",
        )?;

        refund.assert_default_ring()?;
        refund
            .data_hash
            .assert_equal(&zero(), "the refund is not a token note")?;
        refund
            .asset
            .assert_equal(&order.asset, "the refund changes the order's source asset")?;
        refund.amount.assert_equal(
            &private.order_amount.var(),
            "the refund does not return the full order amount",
        )?;
        refund.owner_hash.assert_equal(
            &private.recipient_owner_hash,
            "the refund belongs to another recipient",
        )?;

        let blinding_seed = poseidon(&[constant(0x4443_4e4cu64), order.blinding.clone()])?;
        check_transaction_blindings(
            &public.first_nullifier,
            &blinding_seed,
            &private.private_tx_blinding,
            &[&refund.blinding],
        )?;
        check_private_tx_hash(
            &[order_hash],
            &[refund.hash()?],
            &private.private_tx_blinding,
            &private.private_tx_hash,
        )?;
        Ok(Commitment(public.hash(&private.private_tx_hash)?))
    }
}
