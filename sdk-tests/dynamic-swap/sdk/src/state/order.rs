use anyhow::{anyhow, Result};
use dynamic_swap_program::instructions::shared::u64_right_align;
use solana_address::Address;
use zolana_keypair::{constants::BLINDING_LEN, hash::poseidon};
use zolana_transaction::{
    instructions::{transact::SppProofOutputUtxo, types::SppProofInputUtxo},
    utxo::{Blinding, Utxo},
    Data,
};

use crate::{err, shared_address::SharedShieldedAddress};

/// The two escrow terms an `EscrowUtxo`'s `DataHash` commits to, per
/// `escrow_open.go`'s `checkOrderOutputUtxo`: `DataHash =
/// Poseidon(recipient_owner_hash, MaxPrice, CreatedAt)`. `recipient_owner_hash`
/// must be the taker's owner-hash -- the same owner as the escrowed source UTXO
/// (`SourceIn.Owner`), which is what the circuit commits here. It is never a
/// public input or on-chain field; the payout on settle/refund is bound to it
/// in-circuit and it stays confidential.
///
/// `created_at` is deliberately NOT a field here: it's a slot number the
/// caller picks (a near-future estimate of `Clock::get()?.slot` at execution
/// time) and supplies directly as `CreateEscrowIxData::created_at`, not
/// something `EscrowTerms` can derive. The native `create_escrow` processor
/// cannot pick this value itself and still have the client produce a matching
/// proof in advance, so it only tolerance-checks the caller's value against
/// the real current slot (see `CREATED_AT_SLOT_TOLERANCE` in
/// `program/src/instructions/create_escrow.rs`) rather than trusting or
/// recomputing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EscrowTerms {
    pub recipient_owner_hash: [u8; 32],
    pub max_price: u64,
}

impl EscrowTerms {
    /// The escrow order UTXO's `DataHash`, given a `created_at` slot. Must
    /// equal `CreateEscrowIxData::created_at` (the same value the on-chain
    /// processor tolerance-checks against `Clock::get()?.slot`) or the
    /// `escrow_open` proof will not verify.
    pub fn data_hash(&self, created_at: u64) -> Result<[u8; 32]> {
        poseidon(&[
            &self.recipient_owner_hash,
            &u64_right_align(self.max_price),
            &u64_right_align(created_at),
        ])
        .map_err(err)
    }
}

/// The escrow order UTXO's full preimage: created as an output by
/// `create_escrow`, later spent as an input by `settle`. Owned
/// by the per-pair `escrow_authority` PDA (seeds `[ESCROW_AUTHORITY_PDA_SEED,
/// pair]`), with a constant (zero-secret) nullifier key so the program can
/// always sign for a spend via `invoke_signed` -- mirrors `zk-program-swap`'s
/// `OrderUtxo`/`order_authority_pda`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscrowUtxo {
    pub terms: EscrowTerms,
    pub created_at: u64,
    /// The pair's source asset -- what the user escrows.
    pub asset: Address,
    /// The private `OrderAmount` witness; also this UTXO's own amount.
    pub order_amount: u64,
    pub blinding: Blinding,
}

impl EscrowUtxo {
    pub fn data_hash(&self) -> Result<[u8; 32]> {
        self.terms.data_hash(self.created_at)
    }

    /// The order UTXO as a `create_escrow` output, owned by `owner` (the escrow
    /// authority PDA + shared viewing key). Its encrypted note carries the terms'
    /// `max_price` and the reservation UTXO's `blinding` (see `encode_escrow_note`),
    /// so a party sharing the viewing key can rebuild both escrow UTXOs on settle
    /// without tracking them client-side. `data_hash` still commits the full terms
    /// (`Poseidon(recipient_owner_hash, max_price, created_at)`); the note is
    /// encrypted-only, and its `max_price` is checked against that commitment.
    pub fn output_utxo(
        &self,
        owner: &SharedShieldedAddress,
        reservation_blinding: &Blinding,
    ) -> Result<SppProofOutputUtxo> {
        let note = encode_escrow_note(self.terms.max_price, reservation_blinding);
        Ok(SppProofOutputUtxo {
            asset: self.asset,
            amount: self.order_amount,
            blinding: self.blinding,
            owner_address: Some(owner.shielded_address()?),
            ..Default::default()
        }
        .with_utxo_data(note, self.data_hash()?))
    }

    /// The order UTXO as a `settle` input spend.
    pub fn to_input_utxo(&self, owner: &SharedShieldedAddress) -> Result<SppProofInputUtxo> {
        let utxo = Utxo {
            owner: owner.shielded_address()?.signing_pubkey,
            asset: self.asset,
            amount: self.order_amount,
            blinding: self.blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        Ok(SppProofInputUtxo::new(utxo, owner.nullifier_key()).with_data_hash(self.data_hash()?))
    }
}

/// The reservation UTXO's full preimage: created alongside the order UTXO by
/// `create_escrow` (sized `order_amount * max_price`, the worst-case cost of
/// the escrow at the user's `max_price`), later spent as an input by
/// `settle`. Owned by the same `escrow_authority` PDA as the
/// order UTXO; its `DataHash` commits the order UTXO's own hash so
/// `settle` can prove in-circuit that the reservation being
/// spent really belongs to the `Escrow` account passed into the instruction
/// (see `escrow_open.go`'s `checkReservationOutputUtxo`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    /// The pair's destination asset -- what the pool reserves.
    pub asset: Address,
    pub amount: u64,
    pub blinding: Blinding,
}

impl Reservation {
    /// The reservation UTXO as a `create_escrow` output. `order_utxo_hash` is
    /// the order UTXO's own hash, folded into `DataHash` verbatim (not
    /// re-derived here, so callers that already computed it -- e.g. to
    /// populate `CreateEscrowIxData::escrow_utxo_hash` -- don't recompute it).
    pub fn output_utxo(
        &self,
        owner: &SharedShieldedAddress,
        order_utxo_hash: [u8; 32],
    ) -> Result<SppProofOutputUtxo> {
        Ok(SppProofOutputUtxo {
            asset: self.asset,
            amount: self.amount,
            blinding: self.blinding,
            owner_address: Some(owner.shielded_address()?),
            data_hash: Some(order_utxo_hash),
            ..Default::default()
        })
    }

    /// The reservation UTXO as a `settle` input spend.
    pub fn to_input_utxo(
        &self,
        owner: &SharedShieldedAddress,
        order_utxo_hash: [u8; 32],
    ) -> Result<SppProofInputUtxo> {
        let utxo = Utxo {
            owner: owner.shielded_address()?.signing_pubkey,
            asset: self.asset,
            amount: self.amount,
            blinding: self.blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        Ok(SppProofInputUtxo::new(utxo, owner.nullifier_key()).with_data_hash(order_utxo_hash))
    }
}

/// The order UTXO's encrypted note: `max_price` (8-byte little-endian) followed
/// by the reservation UTXO's `blinding`. The terms' other half,
/// `recipient_owner_hash`, is deliberately absent -- the settler resolves it
/// from the recipient's registered account (both are committed together in the
/// order UTXO's `data_hash`), which keeps the note small enough for
/// `create_escrow` to stay under Solana's transaction size limit.
const ESCROW_NOTE_LEN: usize = 8 + BLINDING_LEN;

/// Encode the order UTXO's note (see `ESCROW_NOTE_LEN`).
pub fn encode_escrow_note(max_price: u64, reservation_blinding: &Blinding) -> Vec<u8> {
    let mut note = Vec::with_capacity(ESCROW_NOTE_LEN);
    note.extend_from_slice(&max_price.to_le_bytes());
    note.extend_from_slice(reservation_blinding);
    note
}

/// Decode the order UTXO's note from a decrypted output's `Data` back into
/// `(max_price, reservation_blinding)`.
pub fn decode_escrow_note(data: &Data) -> Result<(u64, Blinding)> {
    let bytes = data
        .utxo_data()
        .ok_or_else(|| anyhow!("escrow order note carries no utxo data record"))?;
    if bytes.len() != ESCROW_NOTE_LEN {
        return Err(anyhow!(
            "escrow order note is {} bytes, expected {ESCROW_NOTE_LEN}",
            bytes.len()
        ));
    }
    let max_price_bytes = bytes
        .get(..8)
        .ok_or_else(|| anyhow!("escrow note missing max_price"))?;
    let blinding_bytes = bytes
        .get(8..)
        .ok_or_else(|| anyhow!("escrow note missing reservation blinding"))?;
    let max_price = u64::from_le_bytes(
        max_price_bytes
            .try_into()
            .map_err(|_| anyhow!("escrow note max_price length"))?,
    );
    let reservation_blinding: Blinding = blinding_bytes
        .try_into()
        .map_err(|_| anyhow!("escrow note reservation blinding length"))?;
    Ok((max_price, reservation_blinding))
}

#[cfg(test)]
mod tests {
    use zolana_transaction::DataRecord;

    use super::*;

    #[test]
    fn escrow_note_round_trips() {
        let reservation_blinding = [7u8; BLINDING_LEN];
        let note = encode_escrow_note(5, &reservation_blinding);
        assert_eq!(note.len(), ESCROW_NOTE_LEN);

        let data = Data::new(vec![DataRecord::UtxoData(note)]);
        let (max_price, decoded) = decode_escrow_note(&data).expect("decode");
        assert_eq!(max_price, 5);
        assert_eq!(decoded, reservation_blinding);
    }

    #[test]
    fn decode_rejects_missing_record() {
        assert!(decode_escrow_note(&Data::default()).is_err());
    }
}
