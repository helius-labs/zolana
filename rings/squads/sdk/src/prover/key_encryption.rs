//! Key-encryption proof witness builder and prover glue.
//!
//! Mirrors `rings/squads/prover/circuits/key_encryption/{circuit.go,encrypt.go}`.
//! Given a shared viewing secret, a single shared ephemeral secret, a nullifier
//! secret, and the recipient X25519 public keys (recovery + auditor, caller
//! ordered), this builds every ciphertext the circuit verifies, recomputes the
//! public-input hash, proves, and returns the 192-byte compressed proof plus the
//! published artifacts.

use squads_prover::KeyEncryptionProofInputs;
use zolana_keypair::{X25519Keypair, X25519Pubkey};

use crate::prover::{
    error::SquadsProverError,
    shared_viewing_key::{ciphertext_hash, ecdh_encrypt, hash_chain, hash_field, pack33},
};

use squads_prover::KEY_ENCRYPTION_SUPPORTED_KEYS;

/// Inputs to the key-encryption proof. `recipient_keys` is recovery keys first,
/// then auditor keys (the circuit treats them identically; ordering is the
/// on-chain concern, circuit.go:29).
pub struct KeyEncryptionWitness {
    /// Shared viewing secret key (a X25519 secret). Its public key `sk·G` is the
    /// account `shared_viewing_key`; its 32-byte raw form is the plaintext
    /// encrypted to every recipient.
    pub viewing_secret_key: X25519Keypair,
    /// The single shared ephemeral secret (a full-range X25519 secret; the
    /// circuit witnesses it as an raw byte array).
    pub ephemeral_secret_key: X25519Keypair,
    /// The nullifier secret (a BN254-range field element).
    pub nullifier_secret: [u8; 32],
    /// Recovery keys first, then auditor keys.
    pub recipient_keys: Vec<X25519Pubkey>,
    /// Binds the proof to a prior account state on rotation; all-zero at creation.
    pub old_state_hash: [u8; 32],
}

/// One recipient key and the ciphertext of the shared viewing secret encrypted to
/// it, in the order the program reads them.
pub struct RecipientCiphertext {
    pub recipient_pubkey: X25519Pubkey,
    pub ciphertext: Vec<u8>,
}

/// The published artifacts of a key-encryption proof and the proof itself. These
/// are exactly the values the on-chain program recomputes the public-input hash
/// from (see `program/src/shared/key_encryption_proof.rs`).
pub struct KeyEncryptionProofResult {
    /// `c.OldStateHash`.
    pub old_state_hash: [u8; 32],
    /// Compressed shared viewing public key `sk·G`.
    pub shared_viewing_pubkey: X25519Pubkey,
    /// `Poseidon(skLow, skHigh)` shared-viewing-key commitment.
    pub commitment: [u8; 32],
    /// Compressed shared ephemeral public key.
    pub ephemeral_pubkey: X25519Pubkey,
    /// Per-recipient ciphertexts (caller order preserved).
    pub recipient_ciphertexts: Vec<RecipientCiphertext>,
    /// `Poseidon([nullifier_secret])`.
    pub nullifier_pubkey: [u8; 32],
    /// AES-CTR ciphertext of the 31-byte nullifier secret.
    pub nullifier_ciphertext: Vec<u8>,
    /// The public-input hash the circuit constrains and the program recomputes.
    pub public_input_hash: [u8; 32],
    /// The 192-byte compressed Groth16 proof (BSB22 layout, commitment included).
    pub proof: [u8; 192],
}

impl KeyEncryptionWitness {
    /// Build all ciphertexts and the public-input hash, then prove.
    pub fn prove(self) -> Result<KeyEncryptionProofResult, SquadsProverError> {
        let num_keys = self.recipient_keys.len();
        if !KEY_ENCRYPTION_SUPPORTED_KEYS.contains(&num_keys) {
            return Err(SquadsProverError::UnsupportedKeyCount(num_keys));
        }

        // Shared viewing public key sk·G and its 32-byte raw secret (the
        // plaintext encrypted to every recipient). circuit.go:73-82.
        let viewing_pubkey = self.viewing_secret_key.pubkey();
        let viewing_secret_bytes: [u8; 32] = {
            let mut b = [0u8; 32];
            b.copy_from_slice(self.viewing_secret_key.secret_bytes().as_slice());
            b
        };
        let commitment = hash_field(&viewing_secret_bytes)?;

        // Single shared ephemeral key. circuit.go:85-88.
        let ephemeral_pubkey = self.ephemeral_secret_key.pubkey();
        let eph_pk_comp = *ephemeral_pubkey.as_bytes();
        let eph_viewing = self.ephemeral_secret_key.clone();

        // Per-recipient ciphertexts of the 32-byte viewing secret. circuit.go:101-107.
        let mut recipient_ciphertexts = Vec::with_capacity(num_keys);
        for rpk in &self.recipient_keys {
            let rpk_comp = *rpk.as_bytes();
            // dh = ECDH(eph, recipient) = x-coordinate of eph·recipient_pk.
            let dh = eph_viewing
                .ecdh(rpk)
                .map_err(|_| SquadsProverError::InvalidPubkey)?;
            let ciphertext = ecdh_encrypt(
                &dh,
                &eph_pk_comp,
                &rpk_comp,
                &viewing_secret_bytes,
                crate::crypto::SHARED_KEY_INFO,
            )?;
            recipient_ciphertexts.push(RecipientCiphertext {
                recipient_pubkey: *rpk,
                ciphertext,
            });
        }

        // Nullifier: nullifier_pubkey = Poseidon([nullifier_secret]); the 31-byte
        // big-endian nullifier secret is encrypted to sk·G (the shared viewing
        // key) under the same shared ephemeral. circuit.go:113-116.
        let nullifier_pubkey = {
            use zolana_hasher::{Hasher, Poseidon};
            Poseidon::hashv(&[self.nullifier_secret.as_slice()])
                .map_err(|_| SquadsProverError::Poseidon)?
        };
        let null_plaintext = &self.nullifier_secret[1..32]; // 31 big-endian bytes
        let shared_viewing_comp = *viewing_pubkey.as_bytes();
        let dh_null = eph_viewing
            .ecdh(&viewing_pubkey)
            .map_err(|_| SquadsProverError::InvalidPubkey)?;
        let nullifier_ciphertext = ecdh_encrypt(
            &dh_null,
            &eph_pk_comp,
            &shared_viewing_comp,
            null_plaintext,
            crate::crypto::NULLIFIER_INFO,
        )?;

        let public_input_hash = compute_public_input_hash(
            &self.old_state_hash,
            &viewing_pubkey,
            &commitment,
            &ephemeral_pubkey,
            &recipient_ciphertexts,
            &nullifier_pubkey,
            &nullifier_ciphertext,
        )?;

        let proof = self
            .proof_inputs(viewing_secret_bytes, public_input_hash)?
            .prove()?;

        Ok(KeyEncryptionProofResult {
            old_state_hash: self.old_state_hash,
            shared_viewing_pubkey: viewing_pubkey,
            commitment,
            ephemeral_pubkey,
            recipient_ciphertexts,
            nullifier_pubkey,
            nullifier_ciphertext,
            public_input_hash,
            proof,
        })
    }

    fn proof_inputs(
        &self,
        viewing_secret_key: [u8; 32],
        public_input_hash: [u8; 32],
    ) -> Result<KeyEncryptionProofInputs, SquadsProverError> {
        let mut ephemeral_secret_key = [0u8; 32];
        ephemeral_secret_key.copy_from_slice(self.ephemeral_secret_key.secret_bytes().as_slice());
        Ok(KeyEncryptionProofInputs {
            old_state_hash: self.old_state_hash,
            viewing_secret_key,
            ephemeral_secret_key,
            nullifier_secret: self.nullifier_secret,
            recipient_keys: self
                .recipient_keys
                .iter()
                .map(|key| *key.as_bytes())
                .collect(),
            public_input_hash,
        })
    }
}

/// Recompute the circuit's `PublicInputHash`. Chain order mirrors `Circuit.Define`
/// (circuit.go:90-118) and the program's `KeyEncryptionProof::public_input_hash`.
#[allow(clippy::too_many_arguments)]
fn compute_public_input_hash(
    old_state_hash: &[u8; 32],
    shared_viewing_pubkey: &X25519Pubkey,
    commitment: &[u8; 32],
    ephemeral_pubkey: &X25519Pubkey,
    recipient_ciphertexts: &[RecipientCiphertext],
    nullifier_pubkey: &[u8; 32],
    nullifier_ciphertext: &[u8],
) -> Result<[u8; 32], SquadsProverError> {
    let mut chain: Vec<[u8; 32]> = Vec::new();

    chain.push(*old_state_hash);
    let (shared_lo, shared_hi) = pack33(shared_viewing_pubkey.as_bytes());
    chain.push(shared_lo);
    chain.push(shared_hi);
    chain.push(*commitment);
    let (eph_lo, eph_hi) = pack33(ephemeral_pubkey.as_bytes());
    chain.push(eph_lo);
    chain.push(eph_hi);

    for rc in recipient_ciphertexts {
        let (rpk_lo, rpk_hi) = pack33(rc.recipient_pubkey.as_bytes());
        chain.push(rpk_lo);
        chain.push(rpk_hi);
        chain.push(ciphertext_hash(&rc.ciphertext)?);
    }

    chain.push(*nullifier_pubkey);
    chain.push(ciphertext_hash(nullifier_ciphertext)?);

    hash_chain(&chain)
}
