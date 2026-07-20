use sha2::{Digest, Sha256};
pub use zolana_hasher::primitives::{right_align, split_be_128};
use zolana_hasher::{Hasher, Poseidon, Sha256BE};

use crate::{error::KeypairError, pubkey::PublicKey};

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
    let pf = signing_pubkey.owner_proof_input_hash()?;
    Ok(Poseidon::hashv(&[&pf, nullifier_pubkey])?)
}
