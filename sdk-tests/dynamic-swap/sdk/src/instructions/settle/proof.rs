use anyhow::{bail, Result};
use dynamic_swap_program::instructions::{settle::SettlePublicInput, shared::u64_right_align};
use dynamic_swap_prover::{
    EscrowSettleProofInputs, ProofInputUtxo, FUNDER_CHANGE_BLINDING_DOMAIN,
    FUNDER_RECEIPT_BLINDING_DOMAIN, RECIPIENT_BLINDING_DOMAIN,
};
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
    shared::{check_output_utxo, right_align_blinding},
};

/// Deterministically derives a settle/cancel output UTXO's blinding from one
/// input blinding and a per-slot `domain`. The recipient output derives from
/// the order blinding, so the taker precomputes its payout (and refund) note at
/// creation; the funder outputs derive from the funding blinding the funder
/// picked. Mirrors `escrow_settle.go`'s `DeriveOutputBlinding`: keep bytes
/// `[1..32]` of the Poseidon output (its low 248 bits).
pub fn derive_output_blinding(blinding: &Blinding, domain: u64) -> Result<Blinding> {
    let derived = poseidon(&[&right_align_blinding(blinding), &u64_right_align(domain)])
        .map_err(err)?;
    // The circuits derive the blinding with a 31-byte truncation
    // (`DeriveOutputBlinding` keeps the low 248 bits), so mirror it: zero the
    // top byte of the Poseidon output.
    let mut blinding = derived;
    blinding[0] = 0;
    Ok(blinding)
}

/// Proof-input params for the `escrow_settle` circuit: 2-in (order, maker
/// funding) / 3-out (recipient payout, funder change, funder receipt), the
/// exact IN2_OUT3 shape. There is no refund branch: settle always pays
/// `order_amount * execution_price` of the destination asset to the recipient
/// committed as the order UTXO's data hash. The recipient owner-hash is taken
/// from `order_in`'s data hash -- never a public input, so the payout
/// destination stays confidential.
pub struct SettleProofInputParams {
    pub order_in: SppProofInputUtxo,
    pub maker_funding: SppProofInputUtxo,
    pub recipient_out: SppProofOutputUtxo,
    pub funder_change: SppProofOutputUtxo,
    pub funder_receipt: SppProofOutputUtxo,
    /// The escrow's `execution_price` (the stored public pair price, always
    /// nonzero).
    pub execution_price: u64,
    pub order_amount: u64,
    /// The `Escrow` account's on-chain `order_utxo_hash`. `order_in` must hash
    /// to this value.
    pub order_utxo_hash: [u8; 32],
    /// The `Pair` account's on-chain `destination_asset`; bound to
    /// `MakerFunding.Asset`.
    pub destination_asset: [u8; 32],
    pub external_data_hash: [u8; 32],
}

impl SettleProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<EscrowSettleProofInputs> {
        if self.execution_price == 0 {
            bail!("execution_price must be nonzero");
        }

        let order_in = ProofInputUtxo::try_from(&self.order_in).map_err(err)?;
        let maker_funding = ProofInputUtxo::try_from(&self.maker_funding).map_err(err)?;
        let recipient_out = ProofInputUtxo::try_from(&self.recipient_out).map_err(err)?;
        let funder_change = ProofInputUtxo::try_from(&self.funder_change).map_err(err)?;
        let funder_receipt = ProofInputUtxo::try_from(&self.funder_receipt).map_err(err)?;

        let order_in_hash = order_in.hash().map_err(err)?;
        if order_in_hash != self.order_utxo_hash {
            bail!("order_in does not hash to the on-chain order_utxo_hash");
        }
        if self.order_in.utxo.amount != self.order_amount {
            bail!("order_in amount does not match order_amount");
        }
        if asset_field(&self.maker_funding.utxo.asset).map_err(err)? != self.destination_asset {
            bail!("maker_funding asset does not match the pair destination asset");
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

        // The recipient is paid `owed` of the funding's (destination) asset.
        let recipient_owner = check_output_utxo(
            "recipient_out",
            &self.recipient_out,
            &self.maker_funding.utxo.asset,
            owed,
        )?;
        if recipient_owner.owner_hash().map_err(err)? != recipient_owner_hash {
            bail!("recipient_out owner does not match the order's committed recipient");
        }

        // The funder's change: the unspent funding, back to the funding UTXO's
        // own owner.
        let expected_change = self
            .maker_funding
            .utxo
            .amount
            .checked_sub(owed)
            .ok_or_else(|| err("owed exceeds the maker funding amount"))?;
        let change_owner = check_output_utxo(
            "funder_change",
            &self.funder_change,
            &self.maker_funding.utxo.asset,
            expected_change,
        )?;
        if change_owner.owner_hash().map_err(err)? != maker_funding.owner_hash {
            bail!("funder_change owner does not match the funding owner");
        }

        // The funder's receipt: the full settled source-asset amount.
        let receipt_owner = check_output_utxo(
            "funder_receipt",
            &self.funder_receipt,
            &self.order_in.utxo.asset,
            self.order_amount,
        )?;
        if receipt_owner.owner_hash().map_err(err)? != maker_funding.owner_hash {
            bail!("funder_receipt owner does not match the funding owner");
        }

        // Every output blinding is fixed by the circuit to a deterministic
        // derivation; validate the caller's outputs against it so the proof
        // cannot be built with off-derivation blindings.
        for (label, output, source_blinding, domain) in [
            (
                "recipient_out",
                &self.recipient_out,
                &self.order_in.utxo.blinding,
                RECIPIENT_BLINDING_DOMAIN,
            ),
            (
                "funder_change",
                &self.funder_change,
                &self.maker_funding.utxo.blinding,
                FUNDER_CHANGE_BLINDING_DOMAIN,
            ),
            (
                "funder_receipt",
                &self.funder_receipt,
                &self.maker_funding.utxo.blinding,
                FUNDER_RECEIPT_BLINDING_DOMAIN,
            ),
        ] {
            let expected = derive_output_blinding(source_blinding, domain)?;
            if output.blinding != expected {
                bail!("{label} blinding does not match the derived settle blinding");
            }
        }

        // 2-in/3-out; output order (recipient, funder_change, funder_receipt)
        // must match the circuit's `privateTxHashInputs` and the program.
        let maker_funding_hash = maker_funding.hash().map_err(err)?;
        let private_tx_hash = PrivateTxHash::new(
            &[order_in_hash, maker_funding_hash],
            &[
                recipient_out.hash().map_err(err)?,
                funder_change.hash().map_err(err)?,
                funder_receipt.hash().map_err(err)?,
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
        }
        .hash()
        .map_err(err)?;

        Ok(EscrowSettleProofInputs {
            public_input_hash,
            private_tx_hash,
            execution_price: self.execution_price,
            order_in_hash,
            destination_asset: self.destination_asset,
            order_amount: self.order_amount,
            order_in,
            maker_funding,
            recipient_out,
            funder_change,
            funder_receipt,
            external_data_hash: self.external_data_hash,
        })
    }
}
