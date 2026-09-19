use solana_address::Address;
use zolana_hasher::{
    primitives::{hash_bytes, right_align},
    Hasher, Poseidon,
};
use zolana_interface::tree_slot::tree_id_field;

use super::{Blinding, DUMMY_DOMAIN};
use crate::error::TransactionError;

pub fn ring_program_id_proof_input_hash(
    ring_program_id: &Option<Address>,
) -> Result<[u8; 32], TransactionError> {
    program_id_proof_input_hash(ring_program_id)
}

pub fn program_id_proof_input_hash(
    program_id: &Option<Address>,
) -> Result<[u8; 32], TransactionError> {
    match program_id {
        Some(id) => Ok(hash_bytes(id.as_array())?),
        None => Ok([0u8; 32]),
    }
}

pub fn owner_utxo_hash(
    owner_hash: &[u8; 32],
    blinding: &Blinding,
) -> Result<[u8; 32], TransactionError> {
    let blinding = right_align(blinding);
    Ok(Poseidon::hashv(&[owner_hash, &blinding])?)
}

pub(crate) fn dummy_utxo_hash(
    blinding: &Blinding,
    tree_id: u16,
) -> Result<[u8; 32], TransactionError> {
    let ring_hash = Poseidon::hashv(&[&[0u8; 32], &[0u8; 32]])?;
    let owner_hash = owner_utxo_hash(&[0u8; 32], blinding)?;
    Ok(Poseidon::hashv(&[
        &right_align(&DUMMY_DOMAIN.to_be_bytes()),
        &tree_id_field(tree_id),
        &[0u8; 32],
        &[0u8; 32],
        &[0u8; 32],
        &ring_hash,
        &owner_hash,
    ])?)
}
