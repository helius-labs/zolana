use anyhow::{bail, Result};
use dynamic_swap_program::instructions::{settle::SettlePublicInput, shared::u64_right_align};
use dynamic_swap_prover::{PoolSettleProofInputs, ProofInputUtxo};
use zolana_transaction::{
    instructions::transact::{asset_field, PrivateTxHash, SppProofOutputUtxo},
    utxo::SppProofInputUtxo,
};

use super::settle_blinding_seed;
use crate::{
    err,
    shared::{check_output_utxo, check_pool_output_utxo, transaction_blindings},
    state::order_data_hash,
};

/// Proof-input params for the `pool_settle` circuit: 2-in (order, pool note) /
/// 3-out (recipient payout, pool change, maker receipt), the exact IN2_OUT3
/// shape. The committed private minimum selects a destination-asset fill or a
/// full source-asset refund. The recipient and minimum are reopened from the
/// order input and never become public inputs.
pub struct SettleProofInputParams {
    pub order_in: SppProofInputUtxo,
    /// The spent pool note; must be owned by the pool_authority, hold the
    /// pair's destination asset, and commit `booked_in` as its data hash.
    pub pool_in: SppProofInputUtxo,
    /// The spent pool note's booked value (`pool_in.data_hash` must equal
    /// `u64_right_align(booked_in)`).
    pub pool_booked_in: u64,
    pub recipient_out: SppProofOutputUtxo,
    pub pool_change: SppProofOutputUtxo,
    pub maker_receipt: SppProofOutputUtxo,
    /// The escrow's `execution_price` (the stored public pair price, always
    /// nonzero).
    pub execution_price: u64,
    pub order_amount: u64,
    pub recipient_owner_hash: [u8; 32],
    pub min_price: u64,
    /// The `Escrow` account's on-chain `order_utxo_hash`. `order_in` must hash
    /// to this value.
    pub order_utxo_hash: [u8; 32],
    /// The `Pair` account's on-chain `destination_asset`; bound to the pool
    /// note and the payout.
    pub destination_asset: [u8; 32],
    /// The pool_authority PDA's owner-hash (see
    /// `state::pool_authority_owner_hash`); the program recomputes and binds
    /// the same value to the pool input and change.
    pub pool_authority_owner_hash: [u8; 32],
    /// The pair's immutable `max_order_size`; enters the change note's booked
    /// clamp.
    pub max_order_size: u64,
    /// The `Pair` account's on-chain `maker_receipt_owner_hash`; the receipt
    /// destination.
    pub receipt_owner_hash: [u8; 32],
    pub external_data_hash: [u8; 32],
    /// `SppProofInputs::private_tx_blinding()` under
    /// [`settle_blinding_seed`], the fifth `private_tx_hash` preimage element.
    /// The spent inputs carry their own tree ids.
    pub private_tx_blinding: [u8; 32],
    /// Raw id of the tree the recipient, pool change and maker receipt outputs
    /// are appended to; it is the second element of every output's commitment.
    pub output_tree_id: u16,
}

impl SettleProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<PoolSettleProofInputs> {
        if self.execution_price == 0 {
            bail!("execution_price must be nonzero");
        }

        let order_in = ProofInputUtxo::try_from(&self.order_in).map_err(err)?;
        let pool_in = ProofInputUtxo::try_from(&self.pool_in).map_err(err)?;
        let recipient_out =
            ProofInputUtxo::try_from((&self.recipient_out, self.output_tree_id)).map_err(err)?;
        let pool_change =
            ProofInputUtxo::try_from((&self.pool_change, self.output_tree_id)).map_err(err)?;
        let maker_receipt =
            ProofInputUtxo::try_from((&self.maker_receipt, self.output_tree_id)).map_err(err)?;

        let order_in_hash = order_in.hash().map_err(err)?;
        if order_in_hash != self.order_utxo_hash {
            bail!("order_in does not hash to the on-chain order_utxo_hash");
        }
        if self.order_in.utxo.amount != self.order_amount {
            bail!("order_in amount does not match order_amount");
        }
        if asset_field(&self.pool_in.utxo.asset.asset).map_err(err)? != self.destination_asset {
            bail!("pool_in asset does not match the pair destination asset");
        }
        if pool_in.owner_hash != self.pool_authority_owner_hash {
            bail!("pool_in owner is not the pool_authority owner-hash");
        }
        if self.pool_in.data_hash != Some(u64_right_align(self.pool_booked_in)) {
            bail!("pool_in data hash does not commit pool_booked_in");
        }
        let expected_data_hash = order_data_hash(&self.recipient_owner_hash, self.min_price)?;
        if self.order_in.data_hash != Some(expected_data_hash) {
            bail!("order_in data hash does not commit recipient and min_price");
        }

        let owed = self
            .order_amount
            .checked_mul(self.execution_price)
            .ok_or_else(|| err("order_amount * execution_price overflows"))?;

        let fills = self.execution_price >= self.min_price;
        let recipient_asset = if fills {
            &self.pool_in.utxo.asset.asset
        } else {
            &self.order_in.utxo.asset.asset
        };
        let recipient_amount = if fills { owed } else { self.order_amount };
        let recipient_owner = check_output_utxo(
            "recipient_out",
            &self.recipient_out,
            recipient_asset,
            recipient_amount,
        )?;
        if recipient_owner.owner_hash().map_err(err)? != self.recipient_owner_hash {
            bail!("recipient_out owner does not match the order's committed recipient");
        }

        // The pool change: the unspent pool value, re-locked under the
        // pool_authority with booked reduced by the full reservation (clamped
        // at zero) -- the circuit's `max(booked_in - max_order_size, 0)`.
        let settled_owed = if fills { owed } else { 0 };
        let expected_change = self
            .pool_in
            .utxo
            .amount
            .checked_sub(settled_owed)
            .ok_or_else(|| err("owed exceeds the pool note amount"))?;
        let expected_booked = self.pool_booked_in.saturating_sub(self.max_order_size);
        let change_owner = check_pool_output_utxo(
            "pool_change",
            &self.pool_change,
            &self.pool_in.utxo.asset.asset,
            expected_change,
            expected_booked,
        )?;
        if change_owner.owner_hash().map_err(err)? != self.pool_authority_owner_hash {
            bail!("pool_change owner is not the pool_authority owner-hash");
        }

        let receipt_amount = if fills { self.order_amount } else { 0 };
        let receipt_owner = check_output_utxo(
            "maker_receipt",
            &self.maker_receipt,
            &self.order_in.utxo.asset.asset,
            receipt_amount,
        )?;
        if receipt_owner.owner_hash().map_err(err)? != self.receipt_owner_hash {
            bail!("maker_receipt owner does not match the pair's receipt owner-hash");
        }

        // The circuit fixes every output blinding and the private transaction
        // blinding to SPP's derivation under the order-derived seed and the
        // order's nullifier (input 0), so the taker can recompute its payout.
        let first_nullifier = self.order_in.nullifier();
        let blinding_seed = settle_blinding_seed(&self.order_in.utxo.blinding)?;
        let (private_tx_blinding, output_blindings) =
            transaction_blindings(&first_nullifier, &blinding_seed, 3)?;
        if self.private_tx_blinding != private_tx_blinding {
            bail!("private_tx_blinding must derive from the order opening");
        }
        for (index, (output, expected)) in
            [&self.recipient_out, &self.pool_change, &self.maker_receipt]
                .into_iter()
                .zip(&output_blindings)
                .enumerate()
        {
            if &output.blinding != expected {
                bail!("settle output {index} blinding must derive from the order opening");
            }
        }

        // 2-in/3-out; output order (recipient, pool_change, maker_receipt)
        // must match the circuit's `privateTxHashInputs` and the program.
        let pool_in_hash = pool_in.hash().map_err(err)?;
        let private_tx_hash = PrivateTxHash::new(
            &[order_in_hash, pool_in_hash],
            &[
                recipient_out.hash().map_err(err)?,
                pool_change.hash().map_err(err)?,
                maker_receipt.hash().map_err(err)?,
            ],
            &self.external_data_hash,
            &self.private_tx_blinding,
        )
        .hash()
        .map_err(err)?;

        let public_input_hash = SettlePublicInput {
            private_tx_hash: &private_tx_hash,
            execution_price: self.execution_price,
            order_in_hash: &order_in_hash,
            destination_asset: &self.destination_asset,
            pool_authority_owner_hash: &self.pool_authority_owner_hash,
            max_order_size: self.max_order_size,
            receipt_owner_hash: &self.receipt_owner_hash,
            first_nullifier: &first_nullifier,
        }
        .hash()
        .map_err(err)?;

        Ok(PoolSettleProofInputs {
            public_input_hash,
            private_tx_hash,
            first_nullifier,
            execution_price: self.execution_price,
            order_in_hash,
            destination_asset: self.destination_asset,
            pool_authority_owner_hash: self.pool_authority_owner_hash,
            max_order_size: self.max_order_size,
            receipt_owner_hash: self.receipt_owner_hash,
            order_amount: self.order_amount,
            recipient_owner_hash: self.recipient_owner_hash,
            min_price: self.min_price,
            order_in,
            pool_in,
            recipient_out,
            pool_change,
            maker_receipt,
            external_data_hash: self.external_data_hash,
            private_tx_blinding: self.private_tx_blinding,
        })
    }
}
