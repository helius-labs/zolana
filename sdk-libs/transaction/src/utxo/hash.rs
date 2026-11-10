use solana_address::Address;
use spr_hasher::{
    primitives::{hash_bytes, right_align},
    Hasher, Poseidon,
};

use super::{Blinding, ProofInputUtxo};
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
    ProofInputUtxo::dummy_fields(blinding, tree_id).hash()
}
