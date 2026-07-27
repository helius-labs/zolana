//! Deterministic merge-output recovery (the Poseidon derivations the merge
//! circuit proves) plus the Poseidon key schedule behind [`symmetric_apply`],
//! kept for schemes that encrypt with a pre-shared secret.

use zolana_hasher::primitives::{hash_bytes, pack_be};

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
pub const MERGE_INFO: &[u8; 10] = b"TSPP/merge";

fn fe_u32(x: u32) -> [u8; 32] {
    let mut fe = [0u8; 32];
    fe[28..32].copy_from_slice(&x.to_be_bytes());
    fe
}

/// The merged output's blinding, derived in-circuit from the first (always
/// real) input's blinding and its single-use nullifier. The wallet
/// recovers the output by recomputing this value and checking the resulting
/// UTXO hash against the on-chain output commitment. Field elements are 32-byte
/// big-endian.
pub fn merge_output_blinding(
    first_input_blinding: &[u8; 32],
    first_nullifier: &[u8; 32],
) -> Result<[u8; 32], KeypairError> {
    poseidon(&[
        &fe_u32(DOMAIN_MERGE_OUTPUT_BLINDING_V1),
        first_input_blinding,
        first_nullifier,
    ])
}

/// The published nullifier of a dummy (padding) input slot, derived in-circuit
/// from the first real input's nullifier and the slot index. Deterministic
/// dummies cannot smuggle a real wallet nullifier into a padding slot.
pub fn merge_dummy_nullifier(
    first_nullifier: &[u8; 32],
    slot_index: u8,
) -> Result<[u8; 32], KeypairError> {
    let index = fe_u32(u32::from(slot_index));
    poseidon(&[
        &fe_u32(DOMAIN_MERGE_DUMMY_NULLIFIER),
        first_nullifier,
        &index,
    ])
}

/// Commits a fixed-size ciphertext with the protocol-wide 31-byte hash chain.
pub fn merge_ciphertext_hash<const N: usize>(
    ciphertext: &[u8; N],
) -> Result<[u8; 32], KeypairError> {
    Ok(hash_bytes(ciphertext)?)
}

const NONCE_LEN: usize = 12;

fn key_schedule(
    shared_secret: &[u8; 32],
    info: &[u8; 10],
) -> Result<([u8; 32], [u8; NONCE_LEN]), KeypairError> {
    let [info_field] = pack_be::<10, 1>(info);
    let siloed = poseidon(&[&fe_u32(DOM_SEP_SILO), shared_secret, &info_field])?;
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
    info: &[u8; 10],
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
        assert_eq!(
            DOMAIN_MERGE_OUTPUT_BLINDING_V1,
            u32::from_be_bytes(*b"TMOB")
        );
        assert_eq!(DOMAIN_MERGE_DUMMY_NULLIFIER, u32::from_be_bytes(*b"TMDN"));
    }

    /// Golden vectors, pinned against the Go circuit
    /// (`spp_merge/shared/derivation_test.go`).
    #[test]
    fn recovery_derivations_match_circuit_vectors() {
        let first_blinding = fe_u32(42);
        let first_nullifier = fe_u32(7);
        assert_eq!(
            hex::encode(merge_output_blinding(&first_blinding, &first_nullifier).unwrap()),
            "2f6bd14769ab9af9cdede9526bb87e83ee9ba49a41f8e2b7158b50433f541897",
        );
        assert_ne!(
            merge_output_blinding(&first_blinding, &first_nullifier).unwrap(),
            merge_output_blinding(&first_blinding, &fe_u32(8)).unwrap()
        );
        assert_eq!(
            hex::encode(merge_dummy_nullifier(&first_nullifier, 3).unwrap()),
            "25b36ec4cdd3a53a0a9dc93cc69559307c365c84c595dce88cb257261e05aa80",
        );
        // Domain separation: the two derivations never collide, and the first
        // nullifier and slot index both bind.
        assert_ne!(
            merge_dummy_nullifier(&first_nullifier, 3).unwrap(),
            merge_dummy_nullifier(&first_nullifier, 4).unwrap()
        );
        assert_ne!(
            merge_dummy_nullifier(&first_nullifier, 3).unwrap(),
            merge_dummy_nullifier(&fe_u32(8), 3).unwrap()
        );
    }
}
