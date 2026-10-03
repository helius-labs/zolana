use num_bigint::BigUint;
use solana_address::Address;
use zolana_event::MergeOutputDerivation;
use zolana_hasher::{
    primitives::{right_align, BN254_SCALAR_MODULUS_BE, PACK_BE_CHUNK_BYTES},
    Hasher, Poseidon,
};
use zolana_interface::instruction::instruction_data::merge_transact::{
    MergeMaskNonces, MERGE_MASK_SEED_LEN, MERGE_MINT_CHUNKS,
};
use zolana_keypair::NullifierKey;

use crate::{error::TransactionError, utxo::derive_private_tx_blinding};

pub const DOMAIN_MERGE_OUTPUT_BLINDING_V1: u32 = 0x544d_4f42;
pub const DOMAIN_MERGE_DUMMY_NULLIFIER: u32 = 0x544d_444e;
pub const DOMAIN_MERGE_AMOUNT_MASK: u32 = 0x544d_414d;
pub const DOMAIN_MERGE_MINT_MASK: u32 = 0x544d_4d41;

pub fn merge_output_blinding(
    nullifier_key: &NullifierKey,
    first_nullifier: &[u8; 32],
) -> Result<[u8; 32], TransactionError> {
    Ok(Poseidon::hashv(&[
        &right_align(&DOMAIN_MERGE_OUTPUT_BLINDING_V1.to_be_bytes()),
        &right_align(&nullifier_key.secret()),
        first_nullifier,
    ])?)
}

/// The masked output values a merge proof binds and the instruction
/// publishes, for a mint and amount under one mask seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeMaskedOutput {
    pub masked_amount: [u8; 32],
    pub masked_mint: [[u8; 32]; MERGE_MINT_CHUNKS],
    pub mask_seed: [u8; MERGE_MASK_SEED_LEN],
    pub nonces: MergeMaskNonces,
}

impl MergeMaskedOutput {
    pub fn new(
        nullifier_key: &NullifierKey,
        first_nullifier: &[u8; 32],
        mask_seed: &[u8; MERGE_MASK_SEED_LEN],
        amount: u64,
        mint: &Address,
    ) -> Result<Self, TransactionError> {
        let nonces = MergeMaskNonces::derive(mask_seed)?;
        let [amount_mask, mint_masks @ ..] = merge_masks(nullifier_key, first_nullifier, &nonces)?;
        Ok(Self {
            masked_amount: merge_masked_amount(amount, &amount_mask),
            masked_mint: merge_masked_mint(mint, &mint_masks),
            mask_seed: *mask_seed,
            nonces,
        })
    }

    /// The message a merge event republishes from these values.
    pub fn derivation(&self, output_ring_data_hash: Option<[u8; 32]>) -> MergeOutputDerivation {
        MergeOutputDerivation {
            masked_amount: self.masked_amount,
            masked_mint: self.masked_mint,
            mask_seed: self.mask_seed,
            output_ring_data_hash,
        }
    }

    /// Inverts [`Self::new`] with the owner's key: the amount and mint a merge
    /// published, or `None` when the values do not unmask under this key,
    /// which is what any other owner's merge looks like.
    pub fn open(
        nullifier_key: &NullifierKey,
        first_nullifier: &[u8; 32],
        derivation: &MergeOutputDerivation,
    ) -> Result<Option<(u64, Address)>, TransactionError> {
        let nonces = MergeMaskNonces::derive(&derivation.mask_seed)?;
        let [amount_mask, mint_masks @ ..] = merge_masks(nullifier_key, first_nullifier, &nonces)?;
        Ok(
            merge_unmasked_amount(&derivation.masked_amount, &amount_mask)
                .zip(merge_unmasked_mint(&derivation.masked_mint, &mint_masks)),
        )
    }
}

/// The amount mask followed by the mint chunk masks.
fn merge_masks(
    nullifier_key: &NullifierKey,
    first_nullifier: &[u8; 32],
    nonces: &MergeMaskNonces,
) -> Result<[[u8; 32]; 1 + MERGE_MINT_CHUNKS], TransactionError> {
    Ok([
        merge_amount_mask(nullifier_key, first_nullifier, &nonces.amount)?,
        merge_mint_mask(nullifier_key, first_nullifier, &nonces.mint, 0)?,
        merge_mint_mask(nullifier_key, first_nullifier, &nonces.mint, 1)?,
    ])
}

/// The pad over a merge's output amount. The nonce derives from a seed that is
/// fresh per attempt: two attempts that share a first nullifier would
/// otherwise reuse the pad and publish the difference of their amounts.
pub fn merge_amount_mask(
    nullifier_key: &NullifierKey,
    first_nullifier: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<[u8; 32], TransactionError> {
    Ok(Poseidon::hashv(&[
        &right_align(&DOMAIN_MERGE_AMOUNT_MASK.to_be_bytes()),
        &right_align(&nullifier_key.secret()),
        first_nullifier,
        nonce,
    ])?)
}

/// The pad over chunk `chunk_index` of a merge's output mint, under the same
/// nonce as [`merge_amount_mask`].
pub fn merge_mint_mask(
    nullifier_key: &NullifierKey,
    first_nullifier: &[u8; 32],
    nonce: &[u8; 32],
    chunk_index: u8,
) -> Result<[u8; 32], TransactionError> {
    Ok(Poseidon::hashv(&[
        &right_align(&DOMAIN_MERGE_MINT_MASK.to_be_bytes()),
        &right_align(&nullifier_key.secret()),
        first_nullifier,
        nonce,
        &right_align(&u32::from(chunk_index).to_be_bytes()),
    ])?)
}

/// The value a merge publishes for its output amount: `amount + mask` in the
/// BN254 scalar field, with the mask from [`merge_amount_mask`].
pub fn merge_masked_amount(amount: u64, mask: &[u8; 32]) -> [u8; 32] {
    masked_field(&right_align(&amount.to_be_bytes()), mask)
}

/// Inverts [`merge_masked_amount`]. `None` when the published value does not
/// encode a `u64` under this mask, which is what any other owner's merge looks
/// like.
pub fn merge_unmasked_amount(masked_amount: &[u8; 32], mask: &[u8; 32]) -> Option<u64> {
    let amount = unmasked_field(masked_amount, mask)?;
    let (high, low) = amount.split_at_checked(32 - 8)?;
    if high.iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(u64::from_be_bytes(low.try_into().ok()?))
}

/// The values a merge publishes for its output mint: each `hash_bytes` chunk
/// plus its mask from [`merge_mint_mask`].
pub fn merge_masked_mint(
    mint: &Address,
    masks: &[[u8; 32]; MERGE_MINT_CHUNKS],
) -> [[u8; 32]; MERGE_MINT_CHUNKS] {
    let [prefix_mask, last_mask] = masks;
    let [prefix, last] = merge_mint_chunks(mint);
    [
        masked_field(&prefix, prefix_mask),
        masked_field(&last, last_mask),
    ]
}

/// Inverts [`merge_masked_mint`]. `None` unless both chunks unmask to the
/// canonical packing of some mint.
pub fn merge_unmasked_mint(
    masked_mint: &[[u8; 32]; MERGE_MINT_CHUNKS],
    masks: &[[u8; 32]; MERGE_MINT_CHUNKS],
) -> Option<Address> {
    let [masked_prefix, masked_last] = masked_mint;
    let [prefix_mask, last_mask] = masks;
    let [prefix_pad, prefix @ ..] = unmasked_field(masked_prefix, prefix_mask)?;
    let [last_pad @ .., last] = unmasked_field(masked_last, last_mask)?;
    if prefix_pad != 0 || last_pad.iter().any(|byte| *byte != 0) {
        return None;
    }
    let prefix: [u8; PACK_BE_CHUNK_BYTES] = prefix;
    let mut mint = [last; 32];
    for (byte, value) in mint.iter_mut().zip(prefix) {
        *byte = value;
    }
    Some(Address::new_from_array(mint))
}

/// The two field elements `hash_bytes` packs `mint` into, which the merge
/// proof takes as its witness for the asset.
pub fn merge_mint_chunks(mint: &Address) -> [[u8; 32]; MERGE_MINT_CHUNKS] {
    let [prefix @ .., last] = *mint.as_array();
    [right_align(&prefix), right_align(&[last])]
}

fn masked_field(value: &[u8; 32], mask: &[u8; 32]) -> [u8; 32] {
    let modulus = BigUint::from_bytes_be(&BN254_SCALAR_MODULUS_BE);
    field_bytes(&((BigUint::from_bytes_be(value) + BigUint::from_bytes_be(mask)) % &modulus))
}

/// `masked - mask` in the scalar field, or `None` for a non-canonical
/// published value.
fn unmasked_field(masked: &[u8; 32], mask: &[u8; 32]) -> Option<[u8; 32]> {
    let modulus = BigUint::from_bytes_be(&BN254_SCALAR_MODULUS_BE);
    let masked = BigUint::from_bytes_be(masked);
    if masked >= modulus {
        return None;
    }
    let mask = BigUint::from_bytes_be(mask) % &modulus;
    Some(field_bytes(&((masked + &modulus - mask) % &modulus)))
}

fn field_bytes(value: &BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    let mut out = [0u8; 32];
    if let Some(tail) = out.get_mut(32usize.saturating_sub(bytes.len())..) {
        tail.copy_from_slice(&bytes);
    }
    out
}

pub fn merge_private_tx_blinding(
    nullifier_key: &NullifierKey,
    first_nullifier: &[u8; 32],
) -> Result<[u8; 32], TransactionError> {
    derive_private_tx_blinding(first_nullifier, &right_align(&nullifier_key.secret()))
}

pub fn merge_dummy_nullifier(
    nullifier_key: &NullifierKey,
    first_nullifier: &[u8; 32],
    slot_index: u8,
) -> Result<[u8; 32], TransactionError> {
    Ok(Poseidon::hashv(&[
        &right_align(&DOMAIN_MERGE_DUMMY_NULLIFIER.to_be_bytes()),
        &right_align(&nullifier_key.secret()),
        first_nullifier,
        &right_align(&u32::from(slot_index).to_be_bytes()),
    ])?)
}
