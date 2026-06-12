use light_hasher::{Hasher, Poseidon};
use sha2::{Digest, Sha256};

use crate::error::KeypairError;
use crate::pubkey::PublicKey;

pub fn poseidon(inputs: &[&[u8]]) -> Result<[u8; 32], KeypairError> {
    Poseidon::hashv(inputs).map_err(|e| KeypairError::Poseidon(e.into()))
}

pub fn hash_field(value: &[u8; 32]) -> Result<[u8; 32], KeypairError> {
    let (low, high) = split_be_128(value);
    poseidon(&[&low, &high])
}

pub(crate) fn split_be_128(v: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut low = [0u8; 32];
    let mut high = [0u8; 32];
    high[16..].copy_from_slice(&v[0..16]);
    low[16..].copy_from_slice(&v[16..32]);
    (low, high)
}

pub(crate) fn fe_right_align(bytes: &[u8]) -> Result<[u8; 32], KeypairError> {
    if bytes.len() > 32 {
        return Err(KeypairError::FieldElementTooLong);
    }
    let mut fe = [0u8; 32];
    fe[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(fe)
}

pub(crate) fn bool_fe(b: bool) -> [u8; 32] {
    let mut fe = [0u8; 32];
    if b {
        fe[31] = 1;
    }
    fe
}

pub fn sha256_be(preimage: &[u8]) -> [u8; 32] {
    let mut digest: [u8; 32] = Sha256::digest(preimage).into();
    digest[0] = 0;
    digest
}

pub fn owner_hash(
    signing_pubkey: &PublicKey,
    nullifier_pubkey: &[u8; 32],
) -> Result<[u8; 32], KeypairError> {
    let pf = signing_pubkey.hash()?;
    poseidon(&[&pf, nullifier_pubkey])
}
