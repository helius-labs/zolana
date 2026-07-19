use sha2::{Digest, Sha256};
pub use zolana_hasher::primitives::{bool_fe, pack33, right_align, split_be_128};
use zolana_hasher::{primitives, Hasher, Poseidon, Sha256BE};

use crate::{error::KeypairError, pubkey::PublicKey};

pub fn poseidon(inputs: &[&[u8]]) -> Result<[u8; 32], KeypairError> {
    Poseidon::hashv(inputs).map_err(|e| KeypairError::Poseidon(e.into()))
}

pub fn hash_field(value: &[u8; 32]) -> Result<[u8; 32], KeypairError> {
    primitives::hash_field(value).map_err(|e| KeypairError::Poseidon(e.into()))
}

pub fn sha256_be(preimage: &[u8]) -> [u8; 32] {
    Sha256BE::hash(preimage).expect("the sha256 feature is enabled")
}

pub fn sha256(preimage: &[u8]) -> [u8; 32] {
    Sha256::digest(preimage).into()
}

pub fn owner_hash(
    signing_pubkey: &PublicKey,
    nullifier_pubkey: &[u8; 32],
) -> Result<[u8; 32], KeypairError> {
    let pf = signing_pubkey.owner_pk_field()?;
    poseidon(&[&pf, nullifier_pubkey])
}
