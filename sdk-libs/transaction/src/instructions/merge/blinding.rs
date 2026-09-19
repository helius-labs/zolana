use zolana_hasher::{primitives::right_align, Hasher, Poseidon};
use zolana_keypair::NullifierKey;

use crate::{error::TransactionError, utxo::derive_private_tx_blinding};

pub const DOMAIN_MERGE_OUTPUT_BLINDING_V1: u32 = 0x544d_4f42;
pub const DOMAIN_MERGE_DUMMY_NULLIFIER: u32 = 0x544d_444e;

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
