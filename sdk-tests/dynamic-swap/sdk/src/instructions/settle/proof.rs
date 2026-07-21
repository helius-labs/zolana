use anyhow::{bail, Result};
use dynamic_swap_program::instructions::{settle::SettlePublicInput, shared::u64_right_align};
use dynamic_swap_prover::{
    EscrowSettleProofInputs, ProofInputUtxo, MAKER_COUNTER_BLINDING_DOMAIN,
    MAKER_SOURCE_BLINDING_DOMAIN, RECIPIENT_BLINDING_DOMAIN,
};
use zolana_keypair::{constants::BLINDING_LEN, hash::poseidon};
use zolana_transaction::{
    instructions::{
        transact::{PrivateTxHash, SppProofOutputUtxo},
        types::SppProofInputUtxo,
    },
    utxo::Blinding,
};

use crate::{
    err,
    shared::{check_output_utxo, right_align_blinding},
};

/// Deterministically derives a settle output UTXO's blinding from both escrow
/// input blindings (the order and reservation notes) and a per-slot `domain`.
/// The maker and taker -- who both know the two input blindings -- can recompute
/// their payout notes without an encrypted memo, while a third party (which never
/// learns the input blindings) cannot, so the settle-vs-refund outcome stays
/// hidden. Mirrors `escrow_settle.go`'s `DeriveOutputBlinding`: keep bytes
/// `[1..32]` of the Poseidon output (its low 248 bits).
pub fn derive_settle_output_blinding(
    order_blinding: &Blinding,
    reservation_blinding: &Blinding,
    domain: u64,
) -> Result<Blinding> {
    let derived = poseidon(&[
        &right_align_blinding(order_blinding),
        &right_align_blinding(reservation_blinding),
        &u64_right_align(domain),
    ])
    .map_err(err)?;
    let mut blinding = [0u8; BLINDING_LEN];
    blinding.copy_from_slice(derived.get(1..32).ok_or_else(|| err("blinding tail"))?);
    Ok(blinding)
}

/// Proof-input params for the `escrow_settle` circuit -- the single circuit the
/// `settle` instruction uses for both outcomes: 2-in (order, reservation) /
/// 3-out (recipient, maker counter-asset UTXO, maker source-asset UTXO). The
/// circuit derives the outcome from `is_settle = execution_price <= max_price`
/// (execution_price is always nonzero -- the escrow is priced at creation), so
/// the caller must supply outputs shaped for whichever outcome actually applies;
/// this method computes the expected shape from the same comparison and validates
/// the caller's UTXOs against it.
///
/// `max_price` and `created_at` are private witnesses (bound to the order UTXO's
/// data hash), not public inputs -- keeping `max_price` private is what hides
/// settle-vs-refund.
pub struct SettleProofInputParams {
    pub order_in: SppProofInputUtxo,
    pub reservation_in: SppProofInputUtxo,
    pub recipient_out: SppProofOutputUtxo,
    pub maker_counter: SppProofOutputUtxo,
    pub maker_source: SppProofOutputUtxo,
    /// The escrow's `execution_price` (the public pair price, always nonzero).
    pub execution_price: u64,
    /// Private witness: the order's `max_price` (re-opened from the order UTXO's
    /// data hash in-circuit).
    pub max_price: u64,
    /// Private witness: the order's `created_at` (the third data-hash preimage).
    pub created_at: u64,
    pub order_amount: u64,
    /// The `Escrow` account's on-chain `escrow_utxo_hash`. `order_in` must
    /// hash to this value.
    pub escrow_utxo_hash: [u8; 32],
    /// The `Escrow` account's on-chain `reservation_utxo_hash`.
    /// `reservation_in` must hash to this value.
    pub reservation_utxo_hash: [u8; 32],
    /// Private witness: the taker's owner-hash -- the source UTXO's owner
    /// `escrow_open` committed into the order UTXO's data hash. Not stored
    /// on-chain; the caller supplies it from its own record of the order, and the
    /// circuit binds it via the data-hash commitment (pinned by `OrderInHash`) and
    /// to `RecipientOut.Owner`.
    pub recipient_owner_hash: [u8; 32],
    /// The `Pair` account's on-chain `authority_owner_hash`.
    pub authority_owner_hash: [u8; 32],
    pub external_data_hash: [u8; 32],
}

impl SettleProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<EscrowSettleProofInputs> {
        // Matches the circuit's selector. execution_price is always nonzero (the
        // escrow is priced at creation), so the outcome is purely the comparison.
        let is_settle = self.execution_price != 0 && self.execution_price <= self.max_price;

        let order_in = ProofInputUtxo::try_from(&self.order_in).map_err(err)?;
        let reservation_in = ProofInputUtxo::try_from(&self.reservation_in).map_err(err)?;
        let recipient_out = ProofInputUtxo::try_from(&self.recipient_out).map_err(err)?;
        let maker_counter = ProofInputUtxo::try_from(&self.maker_counter).map_err(err)?;
        let maker_source = ProofInputUtxo::try_from(&self.maker_source).map_err(err)?;

        let order_in_hash = order_in.hash().map_err(err)?;
        let reservation_in_hash = reservation_in.hash().map_err(err)?;

        if order_in_hash != self.escrow_utxo_hash {
            bail!("order_in does not hash to the on-chain escrow_utxo_hash");
        }
        if reservation_in_hash != self.reservation_utxo_hash {
            bail!("reservation_in does not hash to the on-chain reservation_utxo_hash");
        }
        if self.order_in.utxo.amount != self.order_amount {
            bail!("order_in amount does not match order_amount");
        }

        let reserved = self
            .order_amount
            .checked_mul(self.max_price)
            .ok_or_else(|| err("order_amount * max_price overflows"))?;
        if self.reservation_in.utxo.amount != reserved {
            bail!("reservation_in amount does not match order_amount * max_price");
        }

        // Settle: owed = order_amount * execution_price; the maker gets the
        // remainder of the reservation back. Refund: owed = 0, remainder = the
        // full reservation.
        let owed = if is_settle {
            self.order_amount
                .checked_mul(self.execution_price)
                .ok_or_else(|| err("order_amount * execution_price overflows"))?
        } else {
            0
        };
        let remainder = reserved
            .checked_sub(owed)
            .ok_or_else(|| err("owed exceeds reserved"))?;

        // Settle: recipient is paid `owed` of the reservation's (destination)
        // asset. Refund: recipient is paid the full `order_amount` back in the
        // order's (source) asset -- the recipient's owner is identical either way.
        let (recipient_amount, recipient_asset) = if is_settle {
            (owed, self.reservation_in.utxo.asset)
        } else {
            (self.order_amount, self.order_in.utxo.asset)
        };
        let recipient_owner = check_output_utxo(
            "recipient_out",
            &self.recipient_out,
            &recipient_asset,
            recipient_amount,
        )?;
        if recipient_owner.owner_hash().map_err(err)? != self.recipient_owner_hash {
            bail!("recipient_out owner does not match the escrow's recipient");
        }

        // The maker's counter-asset leg: the unspent reservation (remainder), in
        // the reservation's (destination) asset, returned to the maker.
        let maker_counter_owner = check_output_utxo(
            "maker_counter",
            &self.maker_counter,
            &self.reservation_in.utxo.asset,
            remainder,
        )?;
        if maker_counter_owner.owner_hash().map_err(err)? != self.authority_owner_hash {
            bail!("maker_counter owner does not match the pair's authority_owner_hash");
        }

        // Settle: the maker receives the full settled source-asset amount.
        // Refund: the maker's source-asset output is a zero-amount placeholder --
        // present either way so the proof shape never differs, but valueless here.
        let maker_source_amount = if is_settle { self.order_amount } else { 0 };
        let maker_source_owner = check_output_utxo(
            "maker_source",
            &self.maker_source,
            &self.order_in.utxo.asset,
            maker_source_amount,
        )?;
        if maker_source_owner.owner_hash().map_err(err)? != self.authority_owner_hash {
            bail!("maker_source owner does not match the pair's authority_owner_hash");
        }

        // Every output blinding is fixed by the circuit to a deterministic
        // derivation from both input blindings; validate the caller's outputs
        // against it so the proof cannot be built with off-derivation blindings.
        let order_blinding = &self.order_in.utxo.blinding;
        let reservation_blinding = &self.reservation_in.utxo.blinding;
        for (label, output, domain) in [
            (
                "recipient_out",
                &self.recipient_out,
                RECIPIENT_BLINDING_DOMAIN,
            ),
            (
                "maker_counter",
                &self.maker_counter,
                MAKER_COUNTER_BLINDING_DOMAIN,
            ),
            (
                "maker_source",
                &self.maker_source,
                MAKER_SOURCE_BLINDING_DOMAIN,
            ),
        ] {
            let expected =
                derive_settle_output_blinding(order_blinding, reservation_blinding, domain)?;
            if output.blinding != expected {
                bail!("{label} blinding does not match the derived settle blinding");
            }
        }

        // 2-in/3-out; output order (recipient, maker_counter, maker_source) must
        // match the circuit's `privateTxHashInputs` and the program.
        let private_tx_hash = PrivateTxHash::new(
            &[order_in_hash, reservation_in_hash],
            &[
                recipient_out.hash().map_err(err)?,
                maker_counter.hash().map_err(err)?,
                maker_source.hash().map_err(err)?,
            ],
            &self.external_data_hash,
        )
        .hash()
        .map_err(err)?;

        let public_input_hash = SettlePublicInput {
            private_tx_hash: &private_tx_hash,
            execution_price: self.execution_price,
            order_in_hash: &order_in_hash,
            reservation_in_hash: &reservation_in_hash,
            authority_owner_hash: &self.authority_owner_hash,
        }
        .hash()
        .map_err(err)?;

        Ok(EscrowSettleProofInputs {
            public_input_hash,
            private_tx_hash,
            execution_price: self.execution_price,
            max_price: self.max_price,
            created_at: self.created_at,
            order_in_hash,
            reservation_in_hash,
            recipient_owner_hash: self.recipient_owner_hash,
            authority_owner_hash: self.authority_owner_hash,
            order_amount: self.order_amount,
            order_in,
            reservation_in,
            recipient_out,
            maker_counter,
            maker_source,
            external_data_hash: self.external_data_hash,
        })
    }
}
