//! Host side of the merge verifiable-encryption scheme. Mirrors
//! `prover/server/circuits/verifiable-encryption` byte-for-byte: DHKEM(P-256)
//! ECDH, a Poseidon key schedule, and AES-256-CTR. Integrity is provided by the
//! proof (the Poseidon ciphertext hash is folded into the public input hash),
//! not a GCM tag, so this path has no authentication tag.

use p256::SecretKey;

use crate::{
    constants::P256_PUBKEY_LEN,
    encryption::{ctr_apply, ecdh_x},
    error::KeypairError,
    hash::poseidon,
    pubkey::P256Pubkey,
};

/// Domain separators (32-bit ASCII tags), mirroring
/// `circuits/verifiable-encryption/poseidon_kdf.go`.
const DOM_SEP_SHARED_SECRET: u32 = 0x544d_5353; // "TMSS"
const DOM_SEP_SILO: u32 = 0x544d_5349; // "TMSI"
const DOM_SEP_KEY: u32 = 0x544d_534b; // "TMSK" (key_1 = DOM_SEP_KEY + 1 = "TMSL")
const DOM_SEP_NONCE: u32 = 0x544d_534e; // "TMSN"

/// HPKE-style key-schedule info bound into the KDF (spec Merge Proof).
pub const MERGE_INFO: &[u8] = b"TSPP/merge";

fn fe_u32(x: u32) -> [u8; 32] {
    let mut fe = [0u8; 32];
    fe[28..32].copy_from_slice(&x.to_be_bytes());
    fe
}

/// pack32 mirrors Pack32To2FECircuit: lo = bytes[0..31] (big-endian), hi = bytes[31].
fn pack32(b: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut lo = [0u8; 32];
    lo[1..32].copy_from_slice(&b[0..31]);
    let mut hi = [0u8; 32];
    hi[31] = b[31];
    (lo, hi)
}

/// pack33 mirrors Pack33To2FECircuit: lo = bytes[0..31], hi = bytes[31..33] (16-bit).
fn pack33(b: &[u8; P256_PUBKEY_LEN]) -> ([u8; 32], [u8; 32]) {
    let mut lo = [0u8; 32];
    lo[1..32].copy_from_slice(&b[0..31]);
    let mut hi = [0u8; 32];
    hi[30] = b[31];
    hi[31] = b[32];
    (lo, hi)
}

/// pack_info mirrors packInfoTo2FECircuit: lo[0] = len, lo holds info[..split] in
/// its low bytes, hi holds the remainder. `info.len()` must be <= 62.
fn pack_info(info: &[u8]) -> ([u8; 32], [u8; 32]) {
    let len = info.len();
    let split = len.min(31);
    let mut lo = [0u8; 32];
    lo[0] = len as u8;
    lo[32 - split..32].copy_from_slice(&info[..split]);
    let mut hi = [0u8; 32];
    let rem = len - split;
    if rem > 0 {
        hi[32 - rem..32].copy_from_slice(&info[split..len]);
    }
    (lo, hi)
}

fn derive_shared_secret(
    dh: &[u8; 32],
    eph_comp: &[u8; P256_PUBKEY_LEN],
    rpk_comp: &[u8; P256_PUBKEY_LEN],
) -> Result<[u8; 32], KeypairError> {
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

const NONCE_LEN: usize = 12;

fn key_schedule(
    shared_secret: &[u8; 32],
    info: &[u8],
) -> Result<([u8; 32], [u8; NONCE_LEN]), KeypairError> {
    let (info_lo, info_hi) = pack_info(info);
    let siloed = poseidon(&[&fe_u32(DOM_SEP_SILO), shared_secret, &info_lo, &info_hi])?;
    let key_lo = poseidon(&[&fe_u32(DOM_SEP_KEY), &siloed])?;
    let key_hi = poseidon(&[&fe_u32(DOM_SEP_KEY + 1), &siloed])?;
    let mut key = [0u8; 32];
    key[0..16].copy_from_slice(&key_hi[16..32]);
    key[16..32].copy_from_slice(&key_lo[16..32]);
    let nonce_raw = poseidon(&[&fe_u32(DOM_SEP_NONCE), &siloed])?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&nonce_raw[20..32]);
    Ok((key, nonce))
}

fn merge_keys(
    sk: &SecretKey,
    counterparty: &P256Pubkey,
    eph_pk: &P256Pubkey,
    rpk: &P256Pubkey,
) -> Result<([u8; 32], [u8; NONCE_LEN]), KeypairError> {
    let dh = ecdh_x(sk, counterparty)?;
    let shared = derive_shared_secret(&dh, eph_pk.as_bytes(), rpk.as_bytes())?;
    key_schedule(&shared, MERGE_INFO)
}

/// Encrypts the merge bundle plaintext to the owner's viewing key under the
/// ephemeral `tx_viewing_sk`. Returns the ciphertext and the ephemeral public
/// key (`tx_viewing_pk`) the wallet uses to decrypt.
pub fn encrypt_verifiable(
    tx_viewing_sk: &SecretKey,
    user_viewing_pk: &P256Pubkey,
    plaintext: &[u8],
) -> Result<(Vec<u8>, P256Pubkey), KeypairError> {
    let tx_viewing_pk = P256Pubkey::from_p256(&tx_viewing_sk.public_key());
    let (key, nonce) = merge_keys(
        tx_viewing_sk,
        user_viewing_pk,
        &tx_viewing_pk,
        user_viewing_pk,
    )?;
    let mut buf = plaintext.to_vec();
    ctr_apply(&key, &nonce, &mut buf);
    Ok((buf, tx_viewing_pk))
}

/// Decrypts a merge ciphertext with the owner's viewing key.
pub fn decrypt_verifiable(
    user_viewing_sk: &SecretKey,
    tx_viewing_pk: &P256Pubkey,
    ciphertext: &[u8],
) -> Result<Vec<u8>, KeypairError> {
    let user_viewing_pk = P256Pubkey::from_p256(&user_viewing_sk.public_key());
    let (key, nonce) = merge_keys(
        user_viewing_sk,
        tx_viewing_pk,
        tx_viewing_pk,
        &user_viewing_pk,
    )?;
    let mut buf = ciphertext.to_vec();
    ctr_apply(&key, &nonce, &mut buf);
    Ok(buf)
}

/// The merge ciphertext's contribution to the public input hash: the two field
/// limbs of the compressed `tx_viewing_pk` and the Poseidon ciphertext hash, in
/// the order the circuit folds them into the public input.
pub struct MergeCiphertextPublicInputs {
    pub tx_viewing_pk_lo: [u8; 32],
    pub tx_viewing_pk_hi: [u8; 32],
    pub ciphertext_hash: [u8; 32],
}

/// The merge proof's verifiable-encryption contribution to the public input hash:
/// the two field limbs of the compressed `tx_viewing_pk` and the Poseidon
/// ciphertext hash, in the order the circuit folds them
/// (prover/server/circuits/spp_merge/circuit.go publicInputHash).
pub fn merge_public_contribution(
    tx_viewing_pk: &P256Pubkey,
    ciphertext: &[u8],
) -> Result<MergeCiphertextPublicInputs, KeypairError> {
    let (tx_viewing_pk_lo, tx_viewing_pk_hi) = pack33(tx_viewing_pk.as_bytes());
    let ciphertext_hash = merge_ciphertext_hash(ciphertext)?;
    Ok(MergeCiphertextPublicInputs {
        tx_viewing_pk_lo,
        tx_viewing_pk_hi,
        ciphertext_hash,
    })
}

/// Poseidon hash of the ciphertext, mirroring `PoseidonHash(PackBytesBE(ct, 16))`
/// in the circuit. This is the value the merge proof folds into the public input
/// hash in place of a GCM tag.
pub fn merge_ciphertext_hash(ciphertext: &[u8]) -> Result<[u8; 32], KeypairError> {
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

#[cfg(test)]
mod tests {
    use p256::elliptic_curve::rand_core::OsRng;

    use super::*;

    fn pubkey(sk: &SecretKey) -> P256Pubkey {
        P256Pubkey::from_p256(&sk.public_key())
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let tx_sk = SecretKey::random(&mut OsRng);
        let user_sk = SecretKey::random(&mut OsRng);
        let user_pk = pubkey(&user_sk);

        let plaintext: Vec<u8> = (0..71u8).collect();
        let (ciphertext, tx_pk) = encrypt_verifiable(&tx_sk, &user_pk, &plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len());
        assert_ne!(ciphertext, plaintext);

        let recovered = decrypt_verifiable(&user_sk, &tx_pk, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    fn secret_key_from_u32(v: u32) -> SecretKey {
        let mut b = [0u8; 32];
        b[28..32].copy_from_slice(&v.to_be_bytes());
        SecretKey::from_slice(&b).unwrap()
    }

    // Cross-language fixture emitted by the Go circuit host
    // (prover/server/circuits/spp_merge TestPrintMergeVector), which is validated
    // against the circuit via test.IsSolved. A match here proves the Rust host,
    // the Go host, and the in-circuit verifiable encryption all agree byte-for-byte.
    #[test]
    fn matches_circuit_vector() {
        let tx_sk = secret_key_from_u32(123_456_789);
        let user_pk = pubkey(&secret_key_from_u32(7));
        let plaintext: Vec<u8> = (0..71u8).collect();

        let (ciphertext, tx_pk) = encrypt_verifiable(&tx_sk, &user_pk, &plaintext).unwrap();
        let ct_hash = merge_ciphertext_hash(&ciphertext).unwrap();

        assert_eq!(
            hex::encode(tx_pk.as_bytes()),
            "02fb50388f29498d0a93ad25ec4c34037b9d3cc3cca4787eb6fedabe2b3003eac8",
            "tx_viewing_pk mismatch",
        );
        assert_eq!(
            hex::encode(&ciphertext),
            "d52cccc7053c653d83c840fcb12c3a1dd6ac2263a9f4c705d784dfd894234b6b5271590160bddbb7191a0eeb96646aa5397e0acb27b605aec6f1ceadcd2726cab1a675d511f202",
            "ciphertext mismatch",
        );
        assert_eq!(
            hex::encode(ct_hash),
            "2418c4f8d103a80bcc365a28f6172e7cd9cbfe71a301c19f775a64187ed2f453",
            "ciphertext hash mismatch",
        );

        let recovered = decrypt_verifiable(&secret_key_from_u32(7), &tx_pk, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn kdf_is_deterministic() {
        let tx_sk = SecretKey::random(&mut OsRng);
        let user_pk = pubkey(&SecretKey::random(&mut OsRng));
        let pt = vec![7u8; 71];
        let (c1, _) = encrypt_verifiable(&tx_sk, &user_pk, &pt).unwrap();
        let (c2, _) = encrypt_verifiable(&tx_sk, &user_pk, &pt).unwrap();
        assert_eq!(c1, c2);
    }
}
