use sha2::{Digest, Sha256};
pub use zolana_hasher::primitives::right_align;
use zolana_hasher::{Hasher, Poseidon};

use crate::{error::KeypairError, pubkey::PublicKey};

pub fn poseidon(inputs: &[&[u8]]) -> Result<[u8; 32], KeypairError> {
    Poseidon::hashv(inputs).map_err(|e| KeypairError::Poseidon(e.into()))
}

pub fn sha256_be(preimage: &[u8]) -> [u8; 32] {
    let mut digest: [u8; 32] = Sha256::digest(preimage).into();
    digest[0] = 0;
    digest
}

pub fn sha256(preimage: &[u8]) -> [u8; 32] {
    Sha256::digest(preimage).into()
}

pub fn owner_hash(
    signing_pubkey: &PublicKey,
    nullifier_pubkey: &[u8; 32],
) -> Result<[u8; 32], KeypairError> {
    let pf = signing_pubkey.owner_proof_input_hash()?;
    poseidon(&[&pf, nullifier_pubkey])
}
