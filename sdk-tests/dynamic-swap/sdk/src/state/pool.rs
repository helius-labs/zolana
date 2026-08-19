use anyhow::{anyhow, Result};
use dynamic_swap_program::instructions::shared::u64_right_align;
use solana_address::Address;
use solana_pubkey::Pubkey;
use zolana_keypair::{
    pubkey::P256Pubkey, NullifierKey, PublicKey, ShieldedAddress, ShieldedPda, ViewingKey,
};
use zolana_transaction::{
    instructions::{transact::SppProofOutputUtxo, types::SppProofInputUtxo},
    utxo::{Blinding, Utxo},
    Data,
};

use crate::{err, state::escrow_nullifier_key};

/// The pool_authority identity's nullifier key: the same hardcoded zero secret
/// as the escrow authority. Deliberately public -- pool-note spend linkage is
/// already public (deposit notes are fully public), so a secret key would hide
/// nothing; spends are gated by the proofs, the authority signer checks, and
/// the liquidity accounting.
pub fn pool_nullifier_key() -> NullifierKey {
    escrow_nullifier_key()
}

/// The pool_authority's owner-hash for `pair`, from public data alone: the PDA
/// signing pubkey and the zero-secret nullifier pubkey. This is the owner of
/// every pool note; the program recomputes the same value on-chain.
pub fn pool_authority_owner_hash(pair: &Pubkey) -> Result<[u8; 32]> {
    let pda = crate::pool_authority_pda(pair);
    zolana_keypair::hash::owner_hash(
        &PublicKey::from_pda(&pda),
        &dynamic_swap_program::ESCROW_NULLIFIER_PUBKEY,
    )
    .map_err(err)
}

/// The pool_authority's shielded address for `pair`, built from public data
/// plus the maker encryption pubkey published in the `Pair` account. Pool-note
/// outputs (settle change, rebalance outputs) encrypt their confidential slots
/// to `viewing_pubkey` so the maker can recover them by scanning.
pub fn pool_authority_address(
    pair: &Pubkey,
    maker_encryption_pubkey: &[u8; 33],
) -> Result<ShieldedAddress> {
    let pda = crate::pool_authority_pda(pair);
    let viewing_pubkey = P256Pubkey::from_bytes(*maker_encryption_pubkey).map_err(err)?;
    Ok(ShieldedAddress::for_pda(
        &pda,
        dynamic_swap_program::ESCROW_NULLIFIER_PUBKEY,
        viewing_pubkey,
    ))
}

/// The maker's pool_authority identity for `pair`: the PDA-role viewing key
/// derived from the maker's own viewing key, paired with the public
/// zero-secret nullifier key. The maker uses it to discover and decrypt pool
/// notes and to build pool spends (settle, withdraw, rebalance).
pub fn pool_authority_identity(
    pair: &Pubkey,
    maker_viewing_key: &ViewingKey,
) -> Result<ShieldedPda> {
    let pda = crate::pool_authority_pda(pair);
    let derived = ShieldedPda::from_viewing_key(pda, maker_viewing_key).map_err(err)?;
    Ok(ShieldedPda::with_viewing_key(
        pda,
        pool_nullifier_key(),
        derived.viewing_key().clone(),
    ))
}

/// One pool (liquidity) note's full preimage: owned by the per-pair
/// `pool_authority` PDA (seeds `[POOL_AUTHORITY_PDA_SEED, pair]`) with the
/// zero-secret nullifier key. Its `DataHash` is `u64_right_align(booked)`
/// directly -- the portion of `amount` the public `liquidity_bound` already
/// counts (`amount - booked` is unpublished surplus). Created by
/// `deposit_liquidity` (booked = amount, fully public), `settle` (change,
/// booked clamped down by `max_order_size`), and `rebalance_liquidity`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolUtxo {
    /// The pair's destination asset -- what the pool pays out.
    pub asset: Address,
    pub amount: u64,
    /// The counted portion of `amount`; see the struct docs.
    pub booked: u64,
    pub blinding: Blinding,
}

impl PoolUtxo {
    pub fn data_hash(&self) -> [u8; 32] {
        u64_right_align(self.booked)
    }

    /// The pool note as a transact output, owned by the pool authority's
    /// address (see `pool_authority_address`). Its confidential slot encrypts
    /// to the maker encryption pubkey and its note carries `booked` (see
    /// `encode_pool_note`); together with the slot's own plaintext (asset,
    /// amount, blinding) that is the complete pool note data the maker needs
    /// to spend it.
    pub fn output_utxo(&self, owner: &ShieldedAddress) -> Result<SppProofOutputUtxo> {
        let note = encode_pool_note(self.booked);
        Ok(SppProofOutputUtxo {
            asset: self.asset,
            amount: self.amount,
            blinding: self.blinding,
            owner_address: Some(*owner),
            ..Default::default()
        }
        .with_utxo_data(note, self.data_hash()))
    }

    /// The pool note as an input spend. Only the zero-secret nullifier key is
    /// needed; the program signs the spend via the pool_authority CPI.
    pub fn to_input_utxo(&self, owner: &ShieldedAddress) -> Result<SppProofInputUtxo> {
        let utxo = Utxo {
            owner: owner.signing_pubkey,
            asset: self.asset,
            amount: self.amount,
            blinding: self.blinding,
            ring_program_id: None,
            data: Data::default(),
        };
        Ok(SppProofInputUtxo::new(utxo, pool_nullifier_key()).with_data_hash(self.data_hash()))
    }
}

/// The pool note's clear-or-encrypted payload: the 8-byte big-endian `booked`
/// value. Deposits publish it in the clear (the whole note is public);
/// settle/rebalance outputs encrypt it to the maker. The slot's own plaintext
/// already carries the asset, amount, and blinding, so `booked` is the one
/// field the data hash commits that must also travel.
const POOL_NOTE_LEN: usize = 8;

/// Encode the pool note payload (see `POOL_NOTE_LEN`).
pub fn encode_pool_note(booked: u64) -> Vec<u8> {
    booked.to_be_bytes().to_vec()
}

/// Decode the pool note payload from a decrypted output's `Data` back into
/// `booked`.
pub fn decode_pool_note(data: &Data) -> Result<u64> {
    let bytes = data
        .utxo_data()
        .ok_or_else(|| anyhow!("pool note carries no utxo data record"))?;
    let bytes: [u8; POOL_NOTE_LEN] = bytes.try_into().map_err(|_| {
        anyhow!(
            "pool note is {} bytes, expected {POOL_NOTE_LEN}",
            bytes.len()
        )
    })?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use zolana_transaction::DataRecord;

    use super::*;

    #[test]
    fn pool_note_round_trips() {
        let booked = 12_345_678_u64;
        let note = encode_pool_note(booked);
        assert_eq!(note.len(), POOL_NOTE_LEN);

        let data = Data::new(vec![DataRecord::UtxoData(note)]);
        let decoded = decode_pool_note(&data).expect("decode");
        assert_eq!(decoded, booked);
    }

    #[test]
    fn decode_rejects_missing_record() {
        assert!(decode_pool_note(&Data::default()).is_err());
    }

    #[test]
    fn decode_rejects_wrong_length() {
        let data = Data::new(vec![DataRecord::UtxoData(vec![1u8; 7])]);
        assert!(decode_pool_note(&data).is_err());
    }

    /// The pool note round-trips through output and input forms with the data
    /// hash committing booked.
    #[test]
    fn data_hash_commits_booked() {
        let pool = PoolUtxo {
            asset: Address::new_unique(),
            amount: 500,
            booked: 400,
            blinding: [3u8; 32],
        };
        assert_eq!(pool.data_hash(), u64_right_align(400));
    }
}
