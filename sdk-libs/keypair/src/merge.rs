//! Deterministic merge-output recovery (the Poseidon derivations the merge
//! circuit proves) plus the Poseidon key schedule behind [`symmetric_apply`],
//! kept for schemes that encrypt with a pre-shared secret.

use crate::{encryption::ctr_apply, error::KeypairError, hash::poseidon};

/// Domain separators (32-bit ASCII tags) for the Poseidon key schedule,
/// mirroring `circuits/verifiable-encryption/poseidon_kdf.go`.
const DOM_SEP_SILO: u32 = 0x544d_5349; // "TMSI"
const DOM_SEP_KEY: u32 = 0x544d_534b; // "TMSK" (key_1 = DOM_SEP_KEY + 1 = "TMSL")
const DOM_SEP_NONCE: u32 = 0x544d_534e; // "TMSN"

/// Domain separators (32-bit ASCII tags) for the deterministic merge-output
/// recovery scheme, mirroring `circuits/spp_merge/shared/derivation.go`.
pub const DOMAIN_MERGE_OUTPUT_BLINDING_V1: u32 = 0x544d_4f42; // "TMOB"
pub const DOMAIN_MERGE_DUMMY_NULLIFIER: u32 = 0x544d_444e; // "TMDN"

/// HPKE-style key-schedule info string bound into the KDF (spec Merge Proof).
/// Shared by schemes that encrypt with a pre-shared secret via
/// [`symmetric_apply`].
pub const MERGE_INFO: &[u8] = b"TSPP/merge";

fn fe_u32(x: u32) -> [u8; 32] {
    let mut fe = [0u8; 32];
    fe[28..32].copy_from_slice(&x.to_be_bytes());
    fe
}

/// The merged output's blinding, derived in-circuit from the first (always
/// real) input's blinding and the single-use `merge_view_tag`. The wallet
/// recovers the output by recomputing this value and checking the resulting
/// UTXO hash against the on-chain output commitment. Field elements are 32-byte
/// big-endian.
pub fn merge_output_blinding(
    first_input_blinding: &[u8; 32],
    merge_view_tag: &[u8; 32],
) -> Result<[u8; 32], KeypairError> {
    poseidon(&[
        &fe_u32(DOMAIN_MERGE_OUTPUT_BLINDING_V1),
        first_input_blinding,
        merge_view_tag,
    ])
}

/// The published nullifier of a dummy (padding) input slot, derived in-circuit
/// from the single-use `merge_view_tag` and the slot index. Deterministic
/// dummies cannot smuggle a real wallet nullifier into a padding slot.
pub fn merge_dummy_nullifier(
    merge_view_tag: &[u8; 32],
    slot_index: u8,
) -> Result<[u8; 32], KeypairError> {
    let index = fe_u32(u32::from(slot_index));
    poseidon(&[&fe_u32(DOMAIN_MERGE_DUMMY_NULLIFIER), merge_view_tag, &index])
}

/// Poseidon hash of a byte payload, packed as big-endian field elements in
/// 16-byte chunks (`PoseidonHash(PackBytesBE(ct, 16))` in the circuit). Used in
/// place of a GCM tag by the pre-shared-secret encryption schemes.
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

/// Symmetric verifiable encryption: derive the AES-256-CTR key/nonce from a
/// pre-shared `shared_secret` via the same Poseidon key schedule as the
/// circuit's `KeySchedule` + `CTREncrypt`, then apply the keystream.
/// Encryption and decryption are the same operation.
pub fn symmetric_apply(
    shared_secret: &[u8; 32],
    info: &[u8],
    buf: &mut [u8],
) -> Result<(), KeypairError> {
    let (key, nonce) = key_schedule(shared_secret, info)?;
    ctr_apply(&key, &nonce, buf);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The recovery domains are the ASCII tags the Go circuit uses; a drift
    /// here silently breaks wallet recovery, so pin the byte values.
    #[test]
    fn recovery_domains_are_the_ascii_tags() {
        assert_eq!(DOMAIN_MERGE_OUTPUT_BLINDING_V1, u32::from_be_bytes(*b"TMOB"));
        assert_eq!(DOMAIN_MERGE_DUMMY_NULLIFIER, u32::from_be_bytes(*b"TMDN"));
    }

    /// Golden vectors, pinned against the Go circuit
    /// (`spp_merge/shared/derivation_test.go`).
    #[test]
    fn recovery_derivations_match_circuit_vectors() {
        let first_blinding = fe_u32(42);
        let tag = fe_u32(7);
        assert_eq!(
            hex::encode(merge_output_blinding(&first_blinding, &tag).unwrap()),
            "2f6bd14769ab9af9cdede9526bb87e83ee9ba49a41f8e2b7158b50433f541897",
        );
        assert_ne!(
            merge_output_blinding(&first_blinding, &tag).unwrap(),
            merge_output_blinding(&first_blinding, &fe_u32(8)).unwrap()
        );
        assert_eq!(
            hex::encode(merge_dummy_nullifier(&tag, 3).unwrap()),
            "25b36ec4cdd3a53a0a9dc93cc69559307c365c84c595dce88cb257261e05aa80",
        );
        // Domain separation: the two derivations never collide, and the tag
        // and slot index both bind.
        assert_ne!(
            merge_dummy_nullifier(&tag, 3).unwrap(),
            merge_dummy_nullifier(&tag, 4).unwrap()
        );
        assert_ne!(
            merge_dummy_nullifier(&tag, 3).unwrap(),
            merge_dummy_nullifier(&fe_u32(8), 3).unwrap()
        );
    }
}
