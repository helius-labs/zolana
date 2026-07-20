//! Host side of the merge verifiable-encryption scheme. Mirrors
//! `prover/server/circuits/verifiable-encryption` byte-for-byte: DHKEM(P-256)
//! ECDH, a Poseidon key schedule, and AES-256-CTR. Integrity is provided by the
//! proof (the Poseidon ciphertext hash is folded into the public input hash),
//! not a GCM tag, so this path has no authentication tag.

use p256::SecretKey;
use zolana_hasher::{
    primitives::{hash_bytes, pack_be, pack_be_slice, right_align},
    Hasher, Poseidon,
};

use crate::{
    constants::P256_PUBKEY_LEN,
    encryption::{ctr_apply, ecdh_x},
    error::KeypairError,
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
    right_align(&x.to_be_bytes())
}

fn derive_shared_secret(
    dh: &[u8; 32],
    eph_comp: &[u8; P256_PUBKEY_LEN],
    rpk_comp: &[u8; P256_PUBKEY_LEN],
) -> Result<[u8; 32], KeypairError> {
    let [dh_lo, dh_hi] = pack_be::<32, 2>(dh);
    let [eph_lo, eph_hi] = pack_be::<33, 2>(eph_comp);
    let [rpk_lo, rpk_hi] = pack_be::<33, 2>(rpk_comp);
    Ok(Poseidon::hashv(&[
        &fe_u32(DOM_SEP_SHARED_SECRET),
        &dh_lo,
        &dh_hi,
        &eph_lo,
        &eph_hi,
        &rpk_lo,
        &rpk_hi,
    ])?)
}

const NONCE_LEN: usize = 12;

fn key_schedule(
    shared_secret: &[u8; 32],
    info: &[u8],
) -> Result<([u8; 32], [u8; NONCE_LEN]), KeypairError> {
    // Key-schedule context binds the info string as `len_fe || pack_be(info)`
    // after the domain tag and shared secret.
    let silo = fe_u32(DOM_SEP_SILO);
    let info_len = right_align(&(info.len() as u64).to_be_bytes());
    let mut info_chunks = [[0u8; 32]; 2];
    let info_chunks = pack_be_slice(info, &mut info_chunks).map_err(|_| KeypairError::InfoTooLong)?;
    let mut inputs: Vec<&[u8]> = Vec::with_capacity(3 + info_chunks.len());
    inputs.push(silo.as_slice());
    inputs.push(shared_secret.as_slice());
    inputs.push(info_len.as_slice());
    for chunk in info_chunks {
        inputs.push(chunk.as_slice());
    }
    let siloed = Poseidon::hashv(&inputs)?;
    let key_lo = Poseidon::hashv(&[&fe_u32(DOM_SEP_KEY), &siloed])?;
    let key_hi = Poseidon::hashv(&[&fe_u32(DOM_SEP_KEY + 1), &siloed])?;
    let mut key = [0u8; 32];
    key[0..16].copy_from_slice(&key_hi[16..32]);
    key[16..32].copy_from_slice(&key_lo[16..32]);
    let nonce_raw = Poseidon::hashv(&[&fe_u32(DOM_SEP_NONCE), &siloed])?;
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

/// Symmetric verifiable encryption: derive the AES-256-CTR key/nonce from a
/// pre-shared `shared_secret` via the same Poseidon key schedule as the merge
/// scheme (no ECDH), then apply the keystream. Encryption and decryption are the
/// same operation. Mirrors feeding a Poseidon-derived seed to the circuit's
/// `KeySchedule` + `CTREncrypt`.
pub fn symmetric_apply(
    shared_secret: &[u8; 32],
    info: &[u8],
    buf: &mut [u8],
) -> Result<(), KeypairError> {
    let (key, nonce) = key_schedule(shared_secret, info)?;
    ctr_apply(&key, &nonce, buf);
    Ok(())
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
    let [tx_viewing_pk_lo, tx_viewing_pk_hi] = pack_be::<33, 2>(tx_viewing_pk.as_bytes());
    // hash_bytes(ct) is the value the merge proof folds into the public input
    // hash in place of a GCM tag.
    let ciphertext_hash = hash_bytes(ciphertext)?;
    Ok(MergeCiphertextPublicInputs {
        tx_viewing_pk_lo,
        tx_viewing_pk_hi,
        ciphertext_hash,
    })
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
        let ct_hash = hash_bytes(&ciphertext).unwrap();

        assert_eq!(
            hex::encode(tx_pk.as_bytes()),
            "02fb50388f29498d0a93ad25ec4c34037b9d3cc3cca4787eb6fedabe2b3003eac8",
            "tx_viewing_pk mismatch",
        );
        assert_eq!(
            hex::encode(&ciphertext),
            "00668796102e28fade49e957b4aa1e74afb6126081e121be93718c316180782b6229664f85ca09e993beace104007f61cbb4cbef156ed821428138d54e5a51bdba164de05ad1ac",
            "ciphertext mismatch",
        );
        assert_eq!(
            hex::encode(ct_hash),
            "1e0b8420c1ec30030e05082d2e458de0afc2e8fa43491024bac48b2a2bdcb746",
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
