//! Key-encryption proof input builder and prover glue.
//!
//! Mirrors `prover/server/circuits/squads/key_encryption/{circuit.go,encrypt.go}`.
//! Given a shared viewing secret, a single shared ephemeral secret, a nullifier
//! secret, and the recipient P-256 public keys (recovery + auditor, caller
//! ordered), this builds every ciphertext the circuit verifies, recomputes the
//! public-input hash, requests a Groth16 proof from the prover server, and
//! returns the 192-byte compressed proof plus the published artifacts.

use p256::SecretKey;
use serde::Serialize;
use zolana_keypair::{P256Pubkey, ViewingKey};

use crate::{
    crypto::uncompressed_65,
    prover::{
        error::SquadsProverError,
        proof::{gnark_json_to_recursion_proof, gnark_json_to_transact_bytes, RecursionProof},
        server::{fe_hex, send_prove_request},
        shared_viewing_key::{
            ciphertext_hash, ecdh_encrypt, hash_chain, hash_field, pack33, secret_key_from_be,
        },
    },
};

pub use zolana_squads_interface::circuits::KEY_ENCRYPTION_SUPPORTED_KEYS;

/// Inputs to the key-encryption proof. `recipient_keys` is recovery keys first,
/// then auditor keys. The circuit treats them identically. Ordering is the
/// on-chain concern (circuit.go:29).
pub struct KeyEncryptionProofInputs {
    /// Shared viewing secret key (a P-256 scalar). Its public key `sk·G` is the
    /// account `shared_viewing_key`. Its 32-byte big-endian form is the plaintext
    /// encrypted to every recipient.
    pub viewing_secret_key: SecretKey,
    /// The single shared ephemeral secret (a full-range P-256 scalar). The circuit
    /// witnesses it as an emulated P256Fr element.
    pub ephemeral_secret_key: SecretKey,
    /// The nullifier secret (a BN254-range field element).
    pub nullifier_secret: [u8; 32],
    /// Recovery keys first, then auditor keys.
    pub recipient_keys: Vec<P256Pubkey>,
    /// Binds the proof to a prior account state on rotation. All-zero at creation.
    pub old_state_hash: [u8; 32],
}

/// One recipient key and the ciphertext of the shared viewing scalar encrypted to
/// it, in the order the program reads them.
pub struct RecipientCiphertext {
    pub recipient_pubkey: P256Pubkey,
    pub ciphertext: Vec<u8>,
}

/// The published artifacts of a key-encryption proof and the proof itself. These
/// are exactly the values the on-chain program recomputes the public-input hash
/// from (see `program/src/shared/key_encryption_proof.rs`).
pub struct KeyEncryptionProofResult {
    /// `c.OldStateHash`.
    pub old_state_hash: [u8; 32],
    /// Compressed shared viewing public key `sk·G`.
    pub shared_viewing_pubkey: P256Pubkey,
    /// `Poseidon(skLow, skHigh)` shared-viewing-key commitment.
    pub commitment: [u8; 32],
    /// Compressed shared ephemeral public key.
    pub ephemeral_pubkey: P256Pubkey,
    /// Per-recipient ciphertexts (caller order preserved).
    pub recipient_ciphertexts: Vec<RecipientCiphertext>,
    /// `Poseidon([nullifier_secret])`.
    pub nullifier_pubkey: [u8; 32],
    /// AES-CTR ciphertext of the 31-byte nullifier secret.
    pub nullifier_ciphertext: Vec<u8>,
    /// The public-input hash the circuit constrains and the program recomputes.
    pub public_input_hash: [u8; 32],
    /// The chain `public_input_hash` folds, in order. A fold binds this to the
    /// proof, so a leg cannot restate what it encrypted.
    pub public_input_chain: Vec<[u8; 32]>,
    /// The 192-byte compressed Groth16 proof (BSB22 layout, commitment included).
    pub proof: [u8; 192],
    /// The same proof in the form a fold's recursive verifier reads.
    pub recursion_proof: RecursionProof,
}

#[derive(Serialize)]
struct RecipientKeyJson {
    pubkey: Vec<String>,
}

#[derive(Serialize)]
struct KeyEncryptionRequestJson {
    #[serde(rename = "circuitType")]
    circuit_type: String,
    #[serde(rename = "numKeys")]
    num_keys: u32,
    #[serde(rename = "oldStateHash")]
    old_state_hash: String,
    #[serde(rename = "viewingSecretKey")]
    viewing_secret_key: String,
    #[serde(rename = "ephemeralSecretKey")]
    ephemeral_secret_key: String,
    #[serde(rename = "nullifierSecret")]
    nullifier_secret: String,
    #[serde(rename = "recipientKeys")]
    recipient_keys: Vec<RecipientKeyJson>,
    #[serde(rename = "publicInputHash")]
    public_input_hash: String,
}

fn byte_hex(b: u8) -> String {
    format!("0x{b:x}")
}

impl KeyEncryptionProofInputs {
    pub fn prove(
        self,
        server_address: &str,
    ) -> Result<KeyEncryptionProofResult, SquadsProverError> {
        let num_keys = self.recipient_keys.len();
        if !u8::try_from(num_keys).is_ok_and(|keys| KEY_ENCRYPTION_SUPPORTED_KEYS.contains(&keys)) {
            return Err(SquadsProverError::UnsupportedKeyCount(num_keys));
        }

        // circuit.go:73-82.
        let viewing_pubkey = P256Pubkey::from_p256(&self.viewing_secret_key.public_key());
        let viewing_sk_be: [u8; 32] = {
            let mut b = [0u8; 32];
            b.copy_from_slice(self.viewing_secret_key.to_bytes().as_slice());
            b
        };
        let commitment = hash_field(&viewing_sk_be)?;

        // Single shared ephemeral key. circuit.go:85-88.
        let ephemeral_pubkey = P256Pubkey::from_p256(&self.ephemeral_secret_key.public_key());
        let eph_pk_comp = *ephemeral_pubkey.as_bytes();
        let eph_viewing = ViewingKey::from_secret_key(self.ephemeral_secret_key.clone());

        // Per-recipient ciphertexts of the 32-byte viewing scalar. circuit.go:101-107.
        let mut recipient_ciphertexts = Vec::with_capacity(num_keys);
        for rpk in &self.recipient_keys {
            let rpk_comp = *rpk.as_bytes();
            let dh = eph_viewing
                .ecdh(rpk)
                .map_err(|_| SquadsProverError::InvalidPubkey)?;
            let ciphertext = ecdh_encrypt(&dh, &eph_pk_comp, &rpk_comp, &viewing_sk_be)?;
            recipient_ciphertexts.push(RecipientCiphertext {
                recipient_pubkey: *rpk,
                ciphertext,
            });
        }

        // The 31-byte big-endian nullifier secret is encrypted to sk·G (the shared
        // viewing key) under the same shared ephemeral. circuit.go:113-116.
        let nullifier_pubkey = {
            use zolana_hasher::{Hasher, Poseidon};
            Poseidon::hashv(&[self.nullifier_secret.as_slice()])
                .map_err(|_| SquadsProverError::Poseidon)?
        };
        let null_plaintext = &self.nullifier_secret[1..32];
        let shared_viewing_comp = *viewing_pubkey.as_bytes();
        let dh_null = eph_viewing
            .ecdh(&viewing_pubkey)
            .map_err(|_| SquadsProverError::InvalidPubkey)?;
        let nullifier_ciphertext =
            ecdh_encrypt(&dh_null, &eph_pk_comp, &shared_viewing_comp, null_plaintext)?;

        let public_input_chain = key_encryption_public_input_chain(KeyEncryptionPublicInputs {
            old_state_hash: &self.old_state_hash,
            shared_viewing_pubkey: &viewing_pubkey,
            commitment: &commitment,
            ephemeral_pubkey: &ephemeral_pubkey,
            recipient_ciphertexts: &recipient_ciphertexts,
            nullifier_pubkey: &nullifier_pubkey,
            nullifier_ciphertext: &nullifier_ciphertext,
        })?;
        let public_input_hash = hash_chain(&public_input_chain)?;

        let request = self.build_request(&viewing_sk_be, &public_input_hash, num_keys)?;
        let proof_json = send_prove_request(server_address, &request)?;
        let proof = gnark_json_to_transact_bytes(&proof_json)?;
        let recursion_proof = gnark_json_to_recursion_proof(&proof_json)?;

        Ok(KeyEncryptionProofResult {
            old_state_hash: self.old_state_hash,
            shared_viewing_pubkey: viewing_pubkey,
            commitment,
            ephemeral_pubkey,
            recipient_ciphertexts,
            nullifier_pubkey,
            nullifier_ciphertext,
            public_input_hash,
            public_input_chain,
            proof,
            recursion_proof,
        })
    }

    fn build_request(
        &self,
        viewing_sk_be: &[u8; 32],
        public_input_hash: &[u8; 32],
        num_keys: usize,
    ) -> Result<String, SquadsProverError> {
        let mut eph_be = [0u8; 32];
        eph_be.copy_from_slice(self.ephemeral_secret_key.to_bytes().as_slice());

        // The circuit's RecipientKey.Pubkey is the 65-byte UNCOMPRESSED point
        // (0x04 || x || y). It compresses in-circuit (circuit.go:104). The Go
        // marshaller rejects anything but 65 bytes (marshal.go:80).
        let recipient_keys = self
            .recipient_keys
            .iter()
            .map(|rpk| -> Result<RecipientKeyJson, SquadsProverError> {
                let uncompressed = uncompressed_65(rpk)?;
                Ok(RecipientKeyJson {
                    pubkey: uncompressed.iter().map(|b| byte_hex(*b)).collect(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let json = KeyEncryptionRequestJson {
            circuit_type: "squads-key-encryption".to_string(),
            num_keys: num_keys as u32,
            old_state_hash: fe_hex(&self.old_state_hash),
            viewing_secret_key: fe_hex(viewing_sk_be),
            ephemeral_secret_key: fe_hex(&eph_be),
            nullifier_secret: fe_hex(&self.nullifier_secret),
            recipient_keys,
            public_input_hash: fe_hex(public_input_hash),
        };
        serde_json::to_string(&json)
            .map_err(|e| SquadsProverError::RequestSerialize(format!("{e}")))
    }
}

pub(crate) struct KeyEncryptionPublicInputs<'a> {
    pub old_state_hash: &'a [u8; 32],
    pub shared_viewing_pubkey: &'a P256Pubkey,
    pub commitment: &'a [u8; 32],
    pub ephemeral_pubkey: &'a P256Pubkey,
    pub recipient_ciphertexts: &'a [RecipientCiphertext],
    pub nullifier_pubkey: &'a [u8; 32],
    pub nullifier_ciphertext: &'a [u8],
}

/// Order mirrors `Circuit.Define` (circuit.go:90-118) and the program's
/// `KeyEncryptionProof::public_input_hash`.
pub(crate) fn key_encryption_public_input_chain(
    inputs: KeyEncryptionPublicInputs<'_>,
) -> Result<Vec<[u8; 32]>, SquadsProverError> {
    let mut chain: Vec<[u8; 32]> = Vec::new();

    chain.push(*inputs.old_state_hash);
    let (shared_lo, shared_hi) = pack33(inputs.shared_viewing_pubkey.as_bytes());
    chain.push(shared_lo);
    chain.push(shared_hi);
    chain.push(*inputs.commitment);
    let (eph_lo, eph_hi) = pack33(inputs.ephemeral_pubkey.as_bytes());
    chain.push(eph_lo);
    chain.push(eph_hi);

    for rc in inputs.recipient_ciphertexts {
        let (rpk_lo, rpk_hi) = pack33(rc.recipient_pubkey.as_bytes());
        chain.push(rpk_lo);
        chain.push(rpk_hi);
        chain.push(ciphertext_hash(&rc.ciphertext)?);
    }

    chain.push(*inputs.nullifier_pubkey);
    chain.push(ciphertext_hash(inputs.nullifier_ciphertext)?);

    Ok(chain)
}

pub fn scalar_secret_key(scalar_be: &[u8; 32]) -> Result<SecretKey, SquadsProverError> {
    secret_key_from_be(scalar_be)
}
