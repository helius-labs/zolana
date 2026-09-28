use zolana_hasher::{primitives::right_align, Hasher, HasherError, Poseidon};

pub const DATA_HASH_DOMAIN: u32 = u32::from_be_bytes(*b"DATA");
pub const UNIQUE_DATA_HASH_DOMAIN: u32 = u32::from_be_bytes(*b"UNIQ");
pub const CLOSED_DATA_HASH_DOMAIN: u32 = u32::from_be_bytes(*b"CLSD");

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

pub fn closed_data_hash(address: &[u8; 32]) -> Result<[u8; 32], HasherError> {
    Poseidon::hashv(&[
        &right_align(&CLOSED_DATA_HASH_DOMAIN.to_be_bytes()),
        address,
    ])
}
