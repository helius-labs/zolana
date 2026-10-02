use num_bigint::BigUint;
use zolana_hasher::{
    primitives::{right_align, BN254_SCALAR_MODULUS_BE},
    Hasher, Poseidon,
};
use zolana_keypair::NullifierKey;

use crate::{error::TransactionError, utxo::derive_private_tx_blinding};

pub const DOMAIN_MERGE_OUTPUT_BLINDING_V1: u32 = 0x544d_4f42;
pub const DOMAIN_MERGE_DUMMY_NULLIFIER: u32 = 0x544d_444e;
pub const DOMAIN_MERGE_AMOUNT_MASK: u32 = 0x544d_414d;

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

pub fn merge_amount_mask(
    nullifier_key: &NullifierKey,
    first_nullifier: &[u8; 32],
) -> Result<[u8; 32], TransactionError> {
    Ok(Poseidon::hashv(&[
        &right_align(&DOMAIN_MERGE_AMOUNT_MASK.to_be_bytes()),
        &right_align(&nullifier_key.secret()),
        first_nullifier,
    ])?)
}

/// The value a merge publishes for its output amount: `amount + mask` in the
/// BN254 scalar field, with the mask from [`merge_amount_mask`].
pub fn merge_masked_amount(amount: u64, mask: &[u8; 32]) -> [u8; 32] {
    let modulus = BigUint::from_bytes_be(&BN254_SCALAR_MODULUS_BE);
    field_bytes(&((BigUint::from(amount) + BigUint::from_bytes_be(mask)) % &modulus))
}

/// Inverts [`merge_masked_amount`]. `None` when the published value does not
/// encode a `u64` under this mask, which is what any other owner's merge looks
/// like.
pub fn merge_unmasked_amount(masked_amount: &[u8; 32], mask: &[u8; 32]) -> Option<u64> {
    let modulus = BigUint::from_bytes_be(&BN254_SCALAR_MODULUS_BE);
    let masked = BigUint::from_bytes_be(masked_amount);
    if masked >= modulus {
        return None;
    }
    let amount = (masked + &modulus - (BigUint::from_bytes_be(mask) % &modulus)) % &modulus;
    u64::try_from(amount).ok()
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
