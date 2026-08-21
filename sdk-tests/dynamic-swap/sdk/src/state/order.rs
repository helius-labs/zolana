use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_pubkey::Pubkey;
use zolana_keypair::{
    constants::BLINDING_LEN, hash::poseidon, pubkey::P256Pubkey, NullifierKey, ShieldedAddress,
    ShieldedPda, ViewingKey,
};
use zolana_transaction::{
    instructions::{transact::SppProofOutputUtxo, types::SppProofInputUtxo},
    utxo::{Blinding, Utxo},
    Data,
};

use crate::err;

/// The escrow_authority identity's nullifier key: the hardcoded zero secret.
/// Deliberately public -- escrow-note spend linkage is already public
/// (`Escrow.order_utxo_hash` lives in the escrow account), so a secret key
/// would hide nothing, and a public key lets both the maker (settle) and the
/// taker (cancel) build the order spend. Its pubkey is pinned as
/// `dynamic_swap_program::ESCROW_NULLIFIER_PUBKEY`.
pub fn escrow_nullifier_key() -> NullifierKey {
    NullifierKey::from_secret([0u8; BLINDING_LEN])
}

/// The escrow_authority's shielded address for `pair`, built from public data
/// alone: the PDA signing pubkey, the zero-secret nullifier pubkey, and the
/// maker encryption pubkey published in the `Pair` account. The taker uses this
/// to build the order output (its confidential slot encrypts to
/// `viewing_pubkey`, handing the order UTXO data to the maker) and the order
/// input spend for `cancel`.
pub fn escrow_authority_address(
    pair: &Pubkey,
    maker_encryption_pubkey: &[u8; 33],
) -> Result<ShieldedAddress> {
    let pda = crate::escrow_authority_pda(pair);
    let viewing_pubkey = P256Pubkey::from_bytes(*maker_encryption_pubkey).map_err(err)?;
    Ok(ShieldedAddress::for_pda(
        &pda,
        dynamic_swap_program::ESCROW_NULLIFIER_PUBKEY,
        viewing_pubkey,
    ))
}

/// The maker's escrow_authority identity for `pair`: the PDA-role viewing key
/// derived from the maker's own viewing key (its pubkey is what `create_pair`
/// publishes as `Pair::maker_encryption_pubkey`), paired with the public
/// zero-secret nullifier key. The maker uses it to discover and decrypt order
/// UTXO handoffs and to build settle spends.
pub fn escrow_authority_identity(
    pair: &Pubkey,
    maker_viewing_key: &ViewingKey,
) -> Result<ShieldedPda> {
    let pda = crate::escrow_authority_pda(pair);
    let derived = ShieldedPda::from_viewing_key(pda, maker_viewing_key).map_err(err)?;
    Ok(ShieldedPda::with_viewing_key(
        pda,
        escrow_nullifier_key(),
        derived.viewing_key().clone(),
    ))
}

/// The escrow order UTXO's full preimage: created as an output by
/// `create_escrow`, later spent as an input by `settle` (maker) or `cancel`
/// (taker). Owned by the per-pair `escrow_authority` PDA (seeds
/// `[ESCROW_AUTHORITY_PDA_SEED, pair]`) with the zero-secret nullifier key, so
/// whoever holds this preimage can build the spend; the program signs spends
/// via `invoke_signed`. Its `DataHash` is
/// `Poseidon(recipient_owner_hash, min_price)`; the recipient is the same owner
/// as the escrowed source UTXO (`SourceIn.Owner`), which the `escrow_open`
/// circuit binds. Neither value is a public input or on-chain field, so the
/// payout destination and fill condition stay confidential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscrowUtxo {
    /// The taker's owner-hash: one half of the order UTXO's composite
    /// `DataHash`, re-opened by `settle`/`cancel` as the payout destination.
    pub recipient_owner_hash: [u8; 32],
    /// The pair's source asset -- what the taker escrows.
    pub asset: Address,
    /// The private `OrderAmount` witness; also this UTXO's own amount.
    pub order_amount: u64,
    /// The taker's private minimum destination-per-source execution price.
    pub min_price: u64,
    pub blinding: Blinding,
}

impl EscrowUtxo {
    pub fn data_hash(&self) -> Result<[u8; 32]> {
        order_data_hash(&self.recipient_owner_hash, self.min_price)
    }

    /// The order UTXO as a `create_escrow` output, owned by the escrow
    /// authority's address (see `escrow_authority_address`). Its confidential
    /// slot encrypts to the maker encryption pubkey and its note carries the
    /// `recipient_owner_hash` (see `encode_order_note`); together with the
    /// slot's own plaintext (asset, amount, blinding) that is the complete
    /// order UTXO data the maker needs to settle.
    pub fn output_utxo(&self, owner: &ShieldedAddress) -> Result<SppProofOutputUtxo> {
        let note = encode_order_note(&OrderNote {
            recipient_owner_hash: self.recipient_owner_hash,
            min_price: self.min_price,
        });
        Ok(SppProofOutputUtxo {
            asset: self.asset,
            amount: self.order_amount,
            blinding: self.blinding,
            owner_address: Some(*owner),
            ..Default::default()
        }
        .with_utxo_data(note, self.data_hash()?))
    }

    /// The order UTXO as a `settle`/`cancel` input spend. Only the zero-secret
    /// nullifier key is needed -- any holder of this preimage can build it.
    pub fn to_input_utxo(&self, owner: &ShieldedAddress) -> Result<SppProofInputUtxo> {
        let utxo = Utxo {
            owner: owner.signing_pubkey,
            asset: self.asset,
            amount: self.order_amount,
            blinding: self.blinding,
            ring_program_id: None,
            data: Data::default(),
        };
        Ok(SppProofInputUtxo::new(utxo, escrow_nullifier_key()).with_data_hash(self.data_hash()?))
    }
}

pub fn order_data_hash(recipient_owner_hash: &[u8; 32], min_price: u64) -> Result<[u8; 32]> {
    let mut encoded_min_price = [0u8; 32];
    encoded_min_price[24..].copy_from_slice(&min_price.to_be_bytes());
    poseidon(&[recipient_owner_hash, &encoded_min_price]).map_err(err)
}

/// The order UTXO's encrypted note: the 32-byte `recipient_owner_hash` followed
/// by the big-endian 8-byte `min_price`. The confidential slot's own plaintext
/// already carries the asset, amount, and blinding; the maker needs both note
/// fields to re-open the order's composite `DataHash` in the settle proof.
const ORDER_NOTE_LEN: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrderNote {
    pub recipient_owner_hash: [u8; 32],
    pub min_price: u64,
}

/// Encode the order UTXO's note (see `ORDER_NOTE_LEN`).
pub fn encode_order_note(note: &OrderNote) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ORDER_NOTE_LEN);
    bytes.extend_from_slice(&note.recipient_owner_hash);
    bytes.extend_from_slice(&note.min_price.to_be_bytes());
    bytes
}

/// Decode the order UTXO's note from a decrypted output's `Data`.
pub fn decode_order_note(data: &Data) -> Result<OrderNote> {
    let bytes = data
        .utxo_data()
        .ok_or_else(|| anyhow!("escrow order note carries no utxo data record"))?;
    if bytes.len() != ORDER_NOTE_LEN {
        return Err(anyhow!(
            "escrow order note is {} bytes, expected {ORDER_NOTE_LEN}",
            bytes.len()
        ));
    }
    let recipient_owner_hash = bytes
        .get(..32)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| anyhow!("escrow order note has an invalid recipient"))?;
    let encoded_min_price = bytes
        .get(32..)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| anyhow!("escrow order note has an invalid minimum price"))?;
    let min_price = u64::from_be_bytes(encoded_min_price);
    Ok(OrderNote {
        recipient_owner_hash,
        min_price,
    })
}

#[cfg(test)]
mod tests {
    use zolana_transaction::DataRecord;

    use super::*;

    #[test]
    fn order_note_round_trips() {
        let expected = OrderNote {
            recipient_owner_hash: [7u8; 32],
            min_price: 42,
        };
        let note = encode_order_note(&expected);
        assert_eq!(note.len(), ORDER_NOTE_LEN);

        let data = Data::new(vec![DataRecord::UtxoData(note)]);
        let decoded = decode_order_note(&data).expect("decode");
        assert_eq!(decoded, expected);
    }

    #[test]
    fn decode_rejects_missing_record() {
        assert!(decode_order_note(&Data::default()).is_err());
    }

    #[test]
    fn decode_rejects_wrong_length() {
        let data = Data::new(vec![DataRecord::UtxoData(vec![1u8; 39])]);
        assert!(decode_order_note(&data).is_err());
    }

    /// Pins the program's hardcoded constant to the real zero-secret pubkey.
    #[test]
    fn escrow_nullifier_pubkey_matches_zero_secret() {
        assert_eq!(
            dynamic_swap_program::ESCROW_NULLIFIER_PUBKEY,
            escrow_nullifier_key().pubkey().expect("pubkey"),
        );
    }
}
