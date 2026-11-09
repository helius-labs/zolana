use solana_address::Address;
use spr_hasher::{
    primitives::{is_canonical_bn254_scalar_be, right_align},
    Hasher, Poseidon,
};
use spr_keypair::{constants::BLINDING_LEN, NullifierKey, ViewingKey};
use zeroize::Zeroizing;

use crate::{error::TransactionError, utxo::derive_private_tx_blinding};

pub const DOMAIN_MERGE_OUTPUT_BLINDING_V1: u32 = 0x544d_4f42;
pub const DOMAIN_MERGE_DUMMY_NULLIFIER: u32 = 0x544d_444e;
pub const DOMAIN_MERGE_OUTPUT_KEY: u32 = 0x544d_4f4b;
pub const DOMAIN_MERGE_OUTPUT_CIPHERTEXT: u32 = 0x544d_4f43;

/// The nullifier secret, or a private seed under the zero key, where secret zero
/// would make every derivation public.
#[derive(Clone)]
pub struct MergeSeed(Zeroizing<[u8; 32]>);

impl core::fmt::Debug for MergeSeed {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("MergeSeed(..)")
    }
}

impl MergeSeed {
    pub fn from_nullifier_key(nullifier_key: &NullifierKey) -> Result<Self, TransactionError> {
        Self::from_bytes(right_align(&nullifier_key.secret()))
    }

    /// The proof cannot tie a seed to the viewing key, so the viewing key recovers
    /// no merge under another seed.
    pub fn derive(
        viewing_key: &ViewingKey,
        ring_program_id: &Address,
        first_nullifier: &[u8; 32],
    ) -> Result<Self, TransactionError> {
        Ok(Self(Zeroizing::new(viewing_key.merge_seed(
            ring_program_id.as_array(),
            first_nullifier,
        )?)))
    }

    /// The nullifier secret seeds every merge except a zero key's.
    pub fn select(
        nullifier_key: &NullifierKey,
        zero_key_seed: Option<impl FnOnce() -> Result<Self, TransactionError>>,
    ) -> Result<Self, TransactionError> {
        match (Self::from_nullifier_key(nullifier_key), zero_key_seed) {
            (key_seed, None) => key_seed,
            (Ok(_), Some(_)) => Err(TransactionError::MergeSeedWithNullifierKey),
            (Err(_), Some(seed)) => seed(),
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, TransactionError> {
        if bytes == [0; 32] || !is_canonical_bn254_scalar_be(&bytes) {
            return Err(TransactionError::InvalidMergeSeed);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Separated by the first nullifier so no two merges share a key and the seed
    /// is never a cipher key.
    pub fn output_key(&self, first_nullifier: &[u8; 32]) -> Result<[u8; 32], TransactionError> {
        Ok(Poseidon::hashv(&[
            &right_align(&DOMAIN_MERGE_OUTPUT_KEY.to_be_bytes()),
            self.as_bytes(),
            first_nullifier,
        ])?)
    }

    pub fn output_blinding(
        &self,
        first_nullifier: &[u8; 32],
    ) -> Result<[u8; 32], TransactionError> {
        Ok(Poseidon::hashv(&[
            &right_align(&DOMAIN_MERGE_OUTPUT_BLINDING_V1.to_be_bytes()),
            self.as_bytes(),
            first_nullifier,
        ])?)
    }

    pub fn private_tx_blinding(
        &self,
        first_nullifier: &[u8; 32],
    ) -> Result<[u8; 32], TransactionError> {
        derive_private_tx_blinding(first_nullifier, self.as_bytes())
    }

    pub fn dummy_nullifier(
        &self,
        first_nullifier: &[u8; 32],
        slot_index: u8,
    ) -> Result<[u8; 32], TransactionError> {
        Ok(Poseidon::hashv(&[
            &right_align(&DOMAIN_MERGE_DUMMY_NULLIFIER.to_be_bytes()),
            self.as_bytes(),
            first_nullifier,
            &right_align(&u32::from(slot_index).to_be_bytes()),
        ])?)
    }
}

pub fn zero_key_pubkey() -> Result<[u8; 32], TransactionError> {
    Ok(NullifierKey::from_secret([0; BLINDING_LEN]).pubkey()?)
}

pub fn merge_output_key(
    nullifier_key: &NullifierKey,
    first_nullifier: &[u8; 32],
) -> Result<[u8; 32], TransactionError> {
    MergeSeed::from_nullifier_key(nullifier_key)?.output_key(first_nullifier)
}

pub fn merge_output_blinding(
    nullifier_key: &NullifierKey,
    first_nullifier: &[u8; 32],
) -> Result<[u8; 32], TransactionError> {
    MergeSeed::from_nullifier_key(nullifier_key)?.output_blinding(first_nullifier)
}

pub fn merge_private_tx_blinding(
    nullifier_key: &NullifierKey,
    first_nullifier: &[u8; 32],
) -> Result<[u8; 32], TransactionError> {
    MergeSeed::from_nullifier_key(nullifier_key)?.private_tx_blinding(first_nullifier)
}

pub fn merge_dummy_nullifier(
    nullifier_key: &NullifierKey,
    first_nullifier: &[u8; 32],
    slot_index: u8,
) -> Result<[u8; 32], TransactionError> {
    MergeSeed::from_nullifier_key(nullifier_key)?.dummy_nullifier(first_nullifier, slot_index)
}
