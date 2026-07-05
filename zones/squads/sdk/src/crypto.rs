//! Pure-crypto gadgets shared by the prover witness builders and the
//! wallet-facing construction/decryption modules.
//!
//! Relocated verbatim from the prover's `shared_viewing_key.rs` so they are
//! available without the `prover` feature (no network/proof dependencies, just
//! p256/aes/ctr/zolana-hasher). The prover module re-exports these under their
//! former names, so the proven path is byte-for-byte unchanged.
//!
//! Mirrors the circuit gadgets in
//! `prover/server/circuits/zone-utils/{poseidon_kdf.go,p256/*,aes/*}` byte-for-byte:
//! P-256 ECDH, a Poseidon key schedule with the `CT_*` domain separators and EMPTY
//! info, and AES-256-CTR (J0 = nonce || 2). Integrity is provided by the proof (the
//! Poseidon ciphertext hash is bound into the public input hash), not a GCM tag,
//! so this path has no authentication tag.

use aes::Aes256;
use ctr::{
    cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher},
    Ctr32BE,
};
use p256::SecretKey;
use zolana_hasher::{Hasher, Poseidon};

type Aes256Ctr = Ctr32BE<Aes256>;

/// Errors for the pure-crypto gadgets. Kept separate from the prover error so the
/// crypto module carries no prover/network dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Poseidon hashing failed.
    Poseidon,
    /// A 32-byte big-endian value was not a valid P-256 scalar.
    InvalidScalar,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Poseidon => write!(f, "poseidon hashing failed"),
            Self::InvalidScalar => write!(f, "invalid P-256 scalar"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Domain separators from `prover/server/circuits/zone-utils/poseidon_kdf.go:14-19`.
const DOM_SEP_SHARED_SECRET: u32 = 0x4354_5f53; // "CT_S"
const DOM_SEP_SILO: u32 = 0x4354_5f49; // "CT_I"
const DOM_SEP_KEY: u32 = 0x4354_5f4b; // "CT_K" (key_1 = DOM_SEP_KEY + 1 = "CT_L")
const DOM_SEP_NONCE: u32 = 0x4354_5f4e; // "CT_N"

/// CTR nonce length (12 bytes).
pub const NONCE_LEN: usize = 12;

fn poseidon(inputs: &[&[u8]]) -> Result<[u8; 32], CryptoError> {
    Poseidon::hashv(inputs).map_err(|_| CryptoError::Poseidon)
}

fn fe_u32(x: u32) -> [u8; 32] {
    let mut fe = [0u8; 32];
    fe[28..32].copy_from_slice(&x.to_be_bytes());
    fe
}

/// `Pack32To2FECircuit`: lo = bytes[0..31] (big-endian, one zero pad byte),
/// hi = bytes[31]. (poseidon_kdf.go:48)
pub fn pack32(b: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut lo = [0u8; 32];
    lo[1..32].copy_from_slice(&b[0..31]);
    let mut hi = [0u8; 32];
    hi[31] = b[31];
    (lo, hi)
}

/// `Pack33To2FECircuit`: lo = bytes[0..31], hi = bytes[31]*256 + bytes[32].
/// (poseidon_kdf.go:63)
pub fn pack33(b: &[u8; 33]) -> ([u8; 32], [u8; 32]) {
    let mut lo = [0u8; 32];
    lo[1..32].copy_from_slice(&b[0..31]);
    let mut hi = [0u8; 32];
    hi[30] = b[31];
    hi[31] = b[32];
    (lo, hi)
}

/// `packInfoTo2FECircuit` for EMPTY info (infoLen = 0): both limbs are zero.
/// (poseidon_kdf.go:73, called via `KeySchedule(.., nil, 0)` at encrypt.go:56)
fn pack_info_empty() -> ([u8; 32], [u8; 32]) {
    ([0u8; 32], [0u8; 32])
}

/// `DeriveSharedSecret` (poseidon_kdf.go:252): Poseidon over the shared-secret
/// separator and the packed limbs of the DH x-coordinate, the compressed
/// ephemeral pubkey, and the compressed recipient pubkey.
pub fn derive_shared_secret(
    dh: &[u8; 32],
    eph_comp: &[u8; 33],
    rpk_comp: &[u8; 33],
) -> Result<[u8; 32], CryptoError> {
    let (dh_lo, dh_hi) = pack32(dh);
    let (eph_lo, eph_hi) = pack33(eph_comp);
    let (rpk_lo, rpk_hi) = pack33(rpk_comp);
    poseidon(&[
        &fe_u32(DOM_SEP_SHARED_SECRET),
        &dh_lo,
        &dh_hi,
        &eph_lo,
        &eph_hi,
        &rpk_lo,
        &rpk_hi,
    ])
}

/// `KeySchedule` (poseidon_kdf.go:196) with empty info. Returns the AES-256 key
/// and the 12-byte CTR nonce.
pub fn key_schedule(shared_secret: &[u8; 32]) -> Result<([u8; 32], [u8; NONCE_LEN]), CryptoError> {
    let (info_lo, info_hi) = pack_info_empty();
    let siloed = poseidon(&[&fe_u32(DOM_SEP_SILO), shared_secret, &info_lo, &info_hi])?;
    let key_lo = poseidon(&[&fe_u32(DOM_SEP_KEY), &siloed])?;
    let key_hi = poseidon(&[&fe_u32(DOM_SEP_KEY + 1), &siloed])?;
    // key[0..16] = keyHi[16..32], key[16..32] = keyLo[16..32]. (poseidon_kdf.go:224)
    let mut key = [0u8; 32];
    key[0..16].copy_from_slice(&key_hi[16..32]);
    key[16..32].copy_from_slice(&key_lo[16..32]);
    let nonce_raw = poseidon(&[&fe_u32(DOM_SEP_NONCE), &siloed])?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&nonce_raw[20..32]); // last 12 bytes (poseidon_kdf.go:235)
    Ok((key, nonce))
}

/// AES-256-CTR matching `aes/ctr.go`: J0 = nonce || 0x00000001 and the counter is
/// advanced once before the first block, so encryption starts at nonce || 2.
/// CTR is its own inverse, so this both encrypts and decrypts in place.
pub fn ctr_apply(key: &[u8; 32], nonce: &[u8; NONCE_LEN], buf: &mut [u8]) {
    let mut iv = [0u8; 16];
    iv[..NONCE_LEN].copy_from_slice(nonce);
    iv[15] = 2;
    let mut cipher = Aes256Ctr::new(GenericArray::from_slice(key), GenericArray::from_slice(&iv));
    cipher.apply_keystream(buf);
}

/// One verifiable encryption to a recipient. `eph_sk` is the shared ephemeral
/// secret, `recipient_pk_comp`/`dh` describe the recipient.
///
/// `dh = ECDH(eph_sk, recipient)` is the x-coordinate of `eph_sk · recipient_pk`
/// (encrypt.go:54). The caller supplies it because the recipient may be a raw
/// public key (recovery/auditor) or the shared viewing key `sk·G` (nullifier).
pub fn ecdh_encrypt(
    dh: &[u8; 32],
    eph_pk_comp: &[u8; 33],
    recipient_pk_comp: &[u8; 33],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let shared = derive_shared_secret(dh, eph_pk_comp, recipient_pk_comp)?;
    let (key, nonce) = key_schedule(&shared)?;
    let mut buf = plaintext.to_vec();
    ctr_apply(&key, &nonce, &mut buf);
    Ok(buf)
}

/// Inverse of [`ecdh_encrypt`]: recover the plaintext from a ciphertext given the
/// same `dh`, ephemeral pubkey, and recipient pubkey. CTR is symmetric, so this
/// reuses the same key schedule.
pub fn ecdh_decrypt(
    dh: &[u8; 32],
    eph_pk_comp: &[u8; 33],
    recipient_pk_comp: &[u8; 33],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    ecdh_encrypt(dh, eph_pk_comp, recipient_pk_comp, ciphertext)
}

/// `Poseidon(PackBytesBE(ciphertext, 16))` (encrypt.go:58). Each 16-byte chunk
/// (the last may be shorter) is a big-endian field element, right-aligned.
pub fn ciphertext_hash(ciphertext: &[u8]) -> Result<[u8; 32], CryptoError> {
    let chunks: Vec<[u8; 32]> = ciphertext
        .chunks(16)
        .map(|c| {
            let mut fe = [0u8; 32];
            fe[32 - c.len()..32].copy_from_slice(c);
            fe
        })
        .collect();
    let refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    poseidon(&refs)
}

/// `hash_field`: split a 32-byte big-endian value into low/high 128-bit limbs and
/// `Poseidon(low, high)`. Matches the program's `hash_field` (proof.rs) and the
/// viewing-key commitment `Poseidon(skLow, skHigh)` (encrypt.go:31).
pub fn hash_field(value: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let mut low = [0u8; 32];
    let mut high = [0u8; 32];
    high[16..].copy_from_slice(&value[0..16]);
    low[16..].copy_from_slice(&value[16..32]);
    poseidon(&[&low, &high])
}

/// Poseidon hash chain `acc = Poseidon(acc, next)` (acc = first item, empty = 0).
/// Mirrors the program's `hash_chain` (proof.rs) and `gadget.HashChain`.
pub fn hash_chain(items: &[[u8; 32]]) -> Result<[u8; 32], CryptoError> {
    let mut iter = items.iter();
    let Some(first) = iter.next() else {
        return Ok([0u8; 32]);
    };
    let mut acc = *first;
    for item in iter {
        acc = poseidon(&[&acc, item])?;
    }
    Ok(acc)
}

/// Build a P-256 `SecretKey` from a 32-byte big-endian scalar.
pub fn secret_key_from_be(scalar_be: &[u8; 32]) -> Result<SecretKey, CryptoError> {
    SecretKey::from_slice(scalar_be).map_err(|_| CryptoError::InvalidScalar)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Empty-info pack is two zero field elements.
    #[test]
    fn pack_info_empty_is_zero() {
        assert_eq!(pack_info_empty(), ([0u8; 32], [0u8; 32]));
    }

    // hash_field matches the documented low/high split: a 32-byte value v gives
    // Poseidon(v[16..32] right-aligned, v[0..16] right-aligned).
    #[test]
    fn hash_field_matches_split() {
        let mut v = [0u8; 32];
        for (i, b) in v.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut low = [0u8; 32];
        let mut high = [0u8; 32];
        high[16..].copy_from_slice(&v[0..16]);
        low[16..].copy_from_slice(&v[16..32]);
        assert_eq!(hash_field(&v).unwrap(), poseidon(&[&low, &high]).unwrap());
    }

    // ecdh_encrypt then ecdh_decrypt with the same parameters is the identity.
    #[test]
    fn ecdh_round_trip() {
        let dh = [7u8; 32];
        let eph = [2u8; 33];
        let rpk = [3u8; 33];
        let plaintext = b"the quick brown fox jumps over!!";
        let ct = ecdh_encrypt(&dh, &eph, &rpk, plaintext).unwrap();
        assert_ne!(ct.as_slice(), plaintext.as_slice());
        let pt = ecdh_decrypt(&dh, &eph, &rpk, &ct).unwrap();
        assert_eq!(pt.as_slice(), plaintext.as_slice());
    }
}
