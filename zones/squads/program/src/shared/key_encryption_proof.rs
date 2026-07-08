//! Key-encryption proof public-input composition and verification.
//!
//! The chain order here MUST match `Circuit.Define`
//! (prover/server/circuits/squads/key_encryption/circuit.go:90-118)
//! byte-for-byte. Order of recipient keys (recovery first, then auditor) is an
//! on-chain concern (`circuit.go:29-31`); the caller supplies them already
//! ordered.
//!
//! Chain: old_state_hash, shared_pk_lo, shared_pk_hi, commitment, eph_pk_lo,
//! eph_pk_hi, then per recipient key [rpk_lo, rpk_hi, ct_hash], then
//! nullifier_pubkey, null_ct_hash.

use pinocchio::{error::ProgramError, ProgramResult};
use zolana_squads_interface::error::SquadsZoneError;

use super::{
    proof::{
        hash_chain, pack33_to_2fe, pack_bytes_be, poseidon_hash, verify_groth16,
        MAX_POSEIDON_INPUTS,
    },
    shapes::{select_key_encryption_vk, KEY_ENCRYPTION_SUPPORTED_KEYS},
};

const HASH_ERR: SquadsZoneError = SquadsZoneError::ProofHashingFailed;

/// Largest supported recipient-key count; bounds the fixed chain buffer.
const MAX_KEYS: usize =
    KEY_ENCRYPTION_SUPPORTED_KEYS[KEY_ENCRYPTION_SUPPORTED_KEYS.len() - 1] as usize;

/// Fixed chain length for the largest shape: 6 prefix + 3 per key + 2 nullifier.
const MAX_CHAIN: usize = 6 + 3 * MAX_KEYS + 2;

/// One public recipient key (recovery or auditor) and the ciphertext of the
/// shared viewing scalar encrypted to it. `circuit.go:101-107`.
pub struct RecipientKey<'a> {
    /// Compressed P-256 recipient pubkey. `rpkLo, rpkHi = Pack33To2FE(rpkComp)`.
    pub rpk: &'a [u8; 33],
    /// AES-CTR ciphertext of the 32-byte viewing scalar (32 bytes -> 2 FEs).
    /// `ctHash = Poseidon(PackBytesBE(ciphertext, 16))`.
    pub ciphertext: &'a [u8],
}

/// Inputs to recompute the key-encryption circuit's public-input hash, plus the
/// proof. `num_keys` is `recipient_keys.len()` and selects the verifying key.
pub struct KeyEncryptionProof<'a> {
    /// `c.OldStateHash` (0 at creation). `circuit.go:95`.
    pub old_state_hash: [u8; 32],
    /// Compressed shared viewing public key (`sk·G`). `circuit.go:82`
    /// (`sharedPkLo, sharedPkHi`).
    pub shared_pk: &'a [u8; 33],
    /// `Poseidon(skLow, skHigh)` shared-viewing-key commitment. `circuit.go:73,97`.
    pub commitment: [u8; 32],
    /// Compressed shared ephemeral public key. `circuit.go:88` (`ephPkLo, ephPkHi`).
    pub eph_pk: &'a [u8; 33],

    /// Recovery keys first, then auditor keys (caller-ordered). `circuit.go:101`.
    pub recipient_keys: &'a [RecipientKey<'a>],

    /// `Poseidon([nullifier_secret])`. `circuit.go:113,116`.
    pub nullifier_pubkey: [u8; 32],
    /// AES-CTR ciphertext of the 31-byte nullifier secret (31 bytes -> 2 FEs).
    /// `circuit.go:115-116`: `Poseidon(PackBytesBE(null_ciphertext, 16))`.
    pub nullifier_ciphertext: &'a [u8],

    /// The 192-byte compressed Groth16 proof.
    pub proof: &'a [u8; 192],
}

/// `Poseidon(PackBytesBE(ciphertext, 16))` (circuit.go:58 in encrypt.go).
fn ciphertext_hash(ciphertext: &[u8]) -> Result<[u8; 32], ProgramError> {
    let mut fes = [[0u8; 32]; MAX_POSEIDON_INPUTS];
    let n = pack_bytes_be(ciphertext, &mut fes, HASH_ERR)?;
    let used = fes.get(..n).ok_or(HASH_ERR)?;
    poseidon_hash(used, HASH_ERR)
}

impl KeyEncryptionProof<'_> {
    /// Recompute the circuit's `PublicInputHash`. Mirrors `Circuit.Define`
    /// (circuit.go:90-118).
    pub fn public_input_hash(&self) -> Result<[u8; 32], ProgramError> {
        if self.recipient_keys.is_empty() || self.recipient_keys.len() > MAX_KEYS {
            return Err(HASH_ERR.into());
        }

        let mut chain = [[0u8; 32]; MAX_CHAIN];
        let mut len = 0usize;
        let push = |v: [u8; 32], chain: &mut [[u8; 32]; MAX_CHAIN], len: &mut usize| {
            if let Some(slot) = chain.get_mut(*len) {
                *slot = v;
                *len += 1;
            }
        };

        // old_state_hash, shared_pk_lo, shared_pk_hi, commitment, eph_pk_lo,
        // eph_pk_hi. circuit.go:94-99.
        push(self.old_state_hash, &mut chain, &mut len);
        let (shared_lo, shared_hi) = pack33_to_2fe(self.shared_pk);
        push(shared_lo, &mut chain, &mut len);
        push(shared_hi, &mut chain, &mut len);
        push(self.commitment, &mut chain, &mut len);
        let (eph_lo, eph_hi) = pack33_to_2fe(self.eph_pk);
        push(eph_lo, &mut chain, &mut len);
        push(eph_hi, &mut chain, &mut len);

        // Per recipient key: rpk_lo, rpk_hi, ct_hash. circuit.go:101-108.
        for key in self.recipient_keys {
            let (rpk_lo, rpk_hi) = pack33_to_2fe(key.rpk);
            push(rpk_lo, &mut chain, &mut len);
            push(rpk_hi, &mut chain, &mut len);
            push(ciphertext_hash(key.ciphertext)?, &mut chain, &mut len);
        }

        // nullifier_pubkey, null_ct_hash. circuit.go:113-116.
        push(self.nullifier_pubkey, &mut chain, &mut len);
        push(
            ciphertext_hash(self.nullifier_ciphertext)?,
            &mut chain,
            &mut len,
        );

        let used = chain.get(..len).ok_or(HASH_ERR)?;
        hash_chain(used, HASH_ERR)
    }

    /// Select the verifying key for `num_keys` and verify the proof.
    pub fn verify(&self) -> ProgramResult {
        let public_input_hash = self.public_input_hash()?;
        let num_keys = u8::try_from(self.recipient_keys.len())
            .map_err(|_| SquadsZoneError::KeyEncryptionProofVerificationFailed)?;
        let vk = select_key_encryption_vk(num_keys)?;
        verify_groth16(
            self.proof,
            public_input_hash,
            vk,
            SquadsZoneError::InvalidProofEncoding,
            SquadsZoneError::KeyEncryptionProofVerificationFailed,
        )
    }
}
