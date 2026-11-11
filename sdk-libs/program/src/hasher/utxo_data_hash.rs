use spr_hasher::{primitives::right_align, Hasher, HasherError, Poseidon};

pub use spr_instruction::{CLOSED_DATA_HASH_DOMAIN, DATA_HASH_DOMAIN, UNIQUE_DATA_HASH_DOMAIN};

pub fn data_hash(state_hash: &[u8; 32]) -> Result<[u8; 32], HasherError> {
    Poseidon::hashv(&[&right_align(&DATA_HASH_DOMAIN.to_be_bytes()), state_hash])
}

pub fn unique_data_hash(
    address: &[u8; 32],
    state_hash: &[u8; 32],
) -> Result<[u8; 32], HasherError> {
    Poseidon::hashv(&[
        &right_align(&UNIQUE_DATA_HASH_DOMAIN.to_be_bytes()),
        address,
        state_hash,
    ])
}
