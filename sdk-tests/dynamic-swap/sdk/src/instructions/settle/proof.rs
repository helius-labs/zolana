use anyhow::{bail, Result};
use dynamic_swap_program::instructions::{settle::SettlePublicInput, shared::u64_right_align};
use dynamic_swap_prover::{PoolSettleProofInputs, ProofInputUtxo, RECIPIENT_BLINDING_DOMAIN};
use zolana_keypair::hash::poseidon;
use zolana_transaction::{
    instructions::{
        transact::{spp_proof_inputs::asset_field, PrivateTxHash, SppProofOutputUtxo},
        types::SppProofInputUtxo,
    },
    utxo::Blinding,
};

use crate::{
    err,
    shared::{check_output_utxo, check_pool_output_utxo, right_align_blinding},
};

/// Deterministically derives a settle/cancel output UTXO's blinding from one
/// input blinding and a per-slot `domain`. Only the taker-facing outputs
/// derive: the recipient payout (and cancel refund) from the order blinding,
/// so the taker precomputes its note at creation. The maker-side outputs (pool
/// change, maker receipt) use free maker-chosen blindings -- the maker builds
/// every settle proof itself. Mirrors the Go `blinding.DeriveOutputBlinding`:
/// keep bytes `[1..32]` of the Poseidon output (its low 248 bits).
pub fn derive_output_blinding(blinding: &Blinding, domain: u64) -> Result<Blinding> {
    let derived =
        poseidon(&[&right_align_blinding(blinding), &u64_right_align(domain)]).map_err(err)?;
    // The circuits derive the blinding with a 31-byte truncation
    // (`DeriveOutputBlinding` keeps the low 248 bits), so mirror it: zero the
    // top byte of the Poseidon output.
    let mut blinding = derived;
    blinding[0] = 0;
    Ok(blinding)
}

/// Proof-input params for the `pool_settle` circuit: 2-in (order, pool note) /
/// 3-out (recipient payout, pool change, maker receipt), the exact IN2_OUT3
/// shape. There is no refund branch: settle always pays
/// `order_amount * execution_price` of the destination asset to the recipient
/// committed as the order UTXO's data hash, funded from the pool note. The
/// recipient owner-hash is taken from `order_in`'s data hash -- never a public
/// input, so the payout destination stays confidential.
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
}

impl SettleProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<PoolSettleProofInputs> {
        if self.execution_price == 0 {
            bail!("execution_price must be nonzero");
        }

        let order_in = ProofInputUtxo::try_from(&self.order_in).map_err(err)?;
        let pool_in = ProofInputUtxo::try_from(&self.pool_in).map_err(err)?;
        let recipient_out = ProofInputUtxo::try_from(&self.recipient_out).map_err(err)?;
        let pool_change = ProofInputUtxo::try_from(&self.pool_change).map_err(err)?;
        let maker_receipt = ProofInputUtxo::try_from(&self.maker_receipt).map_err(err)?;

        let order_in_hash = order_in.hash().map_err(err)?;
        if order_in_hash != self.order_utxo_hash {
            bail!("order_in does not hash to the on-chain order_utxo_hash");
        }
        if self.order_in.utxo.amount != self.order_amount {
            bail!("order_in amount does not match order_amount");
        }
        if asset_field(&self.pool_in.utxo.asset).map_err(err)? != self.destination_asset {
            bail!("pool_in asset does not match the pair destination asset");
        }
        if pool_in.owner_hash != self.pool_authority_owner_hash {
            bail!("pool_in owner is not the pool_authority owner-hash");
        }
        if self.pool_in.data_hash != Some(u64_right_align(self.pool_booked_in)) {
            bail!("pool_in data hash does not commit pool_booked_in");
        }
        // The recipient the circuit re-opens from the order UTXO's data hash.
        let recipient_owner_hash = self
            .order_in
            .data_hash
            .ok_or_else(|| err("order_in carries no data hash (recipient)"))?;

        let owed = self
            .order_amount
            .checked_mul(self.execution_price)
            .ok_or_else(|| err("order_amount * execution_price overflows"))?;

        // The recipient is paid `owed` of the pool's (destination) asset.
        let recipient_owner = check_output_utxo(
            "recipient_out",
            &self.recipient_out,
            &self.pool_in.utxo.asset,
            owed,
        )?;
        if recipient_owner.owner_hash().map_err(err)? != recipient_owner_hash {
            bail!("recipient_out owner does not match the order's committed recipient");
        }

        // The pool change: the unspent pool value, re-locked under the
        // pool_authority with booked reduced by the full reservation (clamped
        // at zero) -- the circuit's `max(booked_in - max_order_size, 0)`.
        let expected_change = self
            .pool_in
            .utxo
            .amount
            .checked_sub(owed)
            .ok_or_else(|| err("owed exceeds the pool note amount"))?;
        let expected_booked = self.pool_booked_in.saturating_sub(self.max_order_size);
        let change_owner = check_pool_output_utxo(
            "pool_change",
            &self.pool_change,
            &self.pool_in.utxo.asset,
            expected_change,
            expected_booked,
        )?;
        if change_owner.owner_hash().map_err(err)? != self.pool_authority_owner_hash {
            bail!("pool_change owner is not the pool_authority owner-hash");
        }

        // The maker's receipt: the full settled source-asset amount, to the
        // receipt owner-hash stored on the pair.
        let receipt_owner = check_output_utxo(
            "maker_receipt",
            &self.maker_receipt,
            &self.order_in.utxo.asset,
            self.order_amount,
        )?;
        if receipt_owner.owner_hash().map_err(err)? != self.receipt_owner_hash {
            bail!("maker_receipt owner does not match the pair's receipt owner-hash");
        }

        // Only the recipient blinding is derivation-fixed (the taker
        // precomputes its payout note at creation); pool change and receipt
        // blindings are free maker-chosen values.
        let expected_recipient_blinding =
            derive_output_blinding(&self.order_in.utxo.blinding, RECIPIENT_BLINDING_DOMAIN)?;
        if self.recipient_out.blinding != expected_recipient_blinding {
            bail!("recipient_out blinding does not match the derived settle blinding");
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
        }
        .hash()
        .map_err(err)?;

        Ok(PoolSettleProofInputs {
            public_input_hash,
            private_tx_hash,
            execution_price: self.execution_price,
            order_in_hash,
            destination_asset: self.destination_asset,
            pool_authority_owner_hash: self.pool_authority_owner_hash,
            max_order_size: self.max_order_size,
            receipt_owner_hash: self.receipt_owner_hash,
            order_amount: self.order_amount,
            order_in,
            pool_in,
            recipient_out,
            pool_change,
            maker_receipt,
            external_data_hash: self.external_data_hash,
        })
    }
}
