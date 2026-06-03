use light_hasher::{Hasher, Poseidon};
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::pubkey::{PublicKey, SignatureType};

pub fn poseidon(inputs: &[&[u8]]) -> Result<[u8; 32], Error> {
    Poseidon::hashv(inputs).map_err(|_| Error::Poseidon)
}

pub(crate) fn split_be_128(v: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut low = [0u8; 32];
    let mut high = [0u8; 32];
    high[16..].copy_from_slice(&v[0..16]);
    low[16..].copy_from_slice(&v[16..32]);
    (low, high)
}

pub(crate) fn fe_right_align(bytes: &[u8]) -> Result<[u8; 32], Error> {
    if bytes.len() > 32 {
        return Err(Error::FieldElementTooLong);
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

pub fn pubkey_field(pubkey: &PublicKey) -> Result<[u8; 32], Error> {
    match pubkey.signature_type() {
        SignatureType::P256 => {
            let p = pubkey.as_p256()?;
            let x = p.x();
            let (low, high) = split_be_128(&x);
            let x_hash = poseidon(&[&low, &high])?;
            let parity = bool_fe(p.y_is_odd());
            poseidon(&[&parity, &x_hash])
        }
        SignatureType::Ed25519 => {
            let ed = pubkey.as_ed25519()?;
            let (low, high) = split_be_128(&ed);
            poseidon(&[&low, &high])
        }
    }
}

pub fn owner_hash(
    signing_pubkey: &PublicKey,
    nullifier_pubkey: &[u8; 32],
) -> Result<[u8; 32], Error> {
    let pf = pubkey_field(signing_pubkey)?;
    poseidon(&[&pf, nullifier_pubkey])
}
