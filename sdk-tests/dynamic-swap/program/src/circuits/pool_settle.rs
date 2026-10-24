use zolana_program::{
    circuit::{constant, poseidon, zero, Assert, Circuit, PublicInputs, U64},
    conversion::ProofInput,
    CircuitError, ZkProgramCircuit,
};

use super::{
    shared::{check_private_tx_hash, check_transaction_blindings},
    Commitment, ProofInputUtxo,
};

#[derive(Clone, Debug, ZkProgramCircuit)]
pub struct PoolSettle {
    pub private: PoolSettlePrivateInputs,
    pub public: PoolSettlePublicInputs,
}

#[derive(Clone, Debug, ProofInput)]
pub struct PoolSettlePrivateInputs {
    pub private_tx_hash: [u8; 32],
    pub order_amount: u64,
    pub recipient_owner_hash: [u8; 32],
    pub min_price: u64,
    pub order_in: ProofInputUtxo,
    pub pool_in: ProofInputUtxo,
    pub recipient_out: ProofInputUtxo,
    pub pool_change: ProofInputUtxo,
    pub maker_receipt: ProofInputUtxo,
    pub private_tx_blinding: [u8; 32],
}

#[derive(Clone, Debug, PublicInputs)]
pub struct PoolSettlePublicInputs {
    pub execution_price: u64,
    pub order_in_hash: [u8; 32],
    pub destination_asset: [u8; 32],
    pub pool_authority_owner_hash: [u8; 32],
    pub max_order_size: u64,
    pub receipt_owner_hash: [u8; 32],
    pub first_nullifier: [u8; 32],
}

impl Circuit for PoolSettleCircuit {
    type Output = Commitment;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let private = &self.private;
        let public = &self.public;
        let order = &private.order_in;
        let pool = &private.pool_in;
        let recipient = &private.recipient_out;
        let change = &private.pool_change;
        let receipt = &private.maker_receipt;

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
            "the settled order is not the escrow's order",
        )?;
        pool.assert_default_ring()?;
        pool.owner_hash.assert_equal(
            &public.pool_authority_owner_hash,
            "the payout is not funded from program-locked pool liquidity",
        )?;
        pool.asset.assert_equal(
            &public.destination_asset,
            "the pool note holds another destination asset",
        )?;
        let booked = U64::from_var(&pool.data_hash, "the pool booked amount overflows u64")?;

        let blinding_seed = poseidon(&[constant(0x4453_5458u64), order.blinding.clone()])?;
        check_transaction_blindings(
            &public.first_nullifier,
            &blinding_seed,
            &private.private_tx_blinding,
            &[&recipient.blinding, &change.blinding, &receipt.blinding],
        )?;

        public
            .execution_price
            .assert_not_zero("the order has no committed execution price")?;
        let owed = private
            .order_amount
            .checked_mul(&public.execution_price, "the order payout overflows u64")?;
        let fills = private
            .min_price
            .is_less_or_equal(&public.execution_price)?;
        let settled_owed = fills.select(&owed.var(), &zero());

        recipient.assert_default_ring()?;
        recipient
            .data_hash
            .assert_equal(&zero(), "the recipient payout is not a token note")?;
        recipient.asset.assert_equal(
            &fills.select(&pool.asset, &order.asset),
            "the recipient payout holds the wrong asset",
        )?;
        recipient.amount.assert_equal(
            &fills.select(&owed.var(), &private.order_amount.var()),
            "the recipient payout has the wrong fill or refund amount",
        )?;
        recipient.owner_hash.assert_equal(
            &private.recipient_owner_hash,
            "the payout belongs to another recipient",
        )?;

        change.assert_default_ring()?;
        change.owner_hash.assert_equal(
            &public.pool_authority_owner_hash,
            "the pool change is not locked to the pool authority",
        )?;
        change
            .asset
            .assert_equal(&pool.asset, "the pool change holds another asset")?;
        change.amount.assert_equal(
            &pool.amount.minus(&settled_owed),
            "the pool change does not conserve the payout",
        )?;
        let _ = U64::from_var(&change.amount, "the pool cannot fund the order payout")?;
        let covers_reservation = public.max_order_size.is_less_or_equal(&booked)?;
        let booked_out =
            covers_reservation.select(&booked.var().minus(&public.max_order_size.var()), &zero());
        change.data_hash.assert_equal(
            &booked_out,
            "the pool change does not consume the full reservation",
        )?;

        receipt.assert_default_ring()?;
        receipt
            .data_hash
            .assert_equal(&zero(), "the maker receipt is not a token note")?;
        receipt
            .asset
            .assert_equal(&order.asset, "the maker receipt changes the source asset")?;
        receipt.amount.assert_equal(
            &fills.select(&private.order_amount.var(), &zero()),
            "the maker receipt has the wrong filled amount",
        )?;
        receipt.owner_hash.assert_equal(
            &public.receipt_owner_hash,
            "the maker receipt belongs to another owner",
        )?;

        check_private_tx_hash(
            &[order_hash, pool.hash()?],
            &[recipient.hash()?, change.hash()?, receipt.hash()?],
            &private.private_tx_blinding,
            &private.private_tx_hash,
        )?;
        Ok(Commitment(public.hash(&private.private_tx_hash)?))
    }
}
