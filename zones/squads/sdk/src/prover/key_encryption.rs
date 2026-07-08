//! Key-encryption proof witness builder and prover glue.
//!
//! Mirrors `prover/server/circuits/squads/key_encryption/{circuit.go,encrypt.go}`.
//! Given a shared viewing secret, a single shared ephemeral secret, a nullifier
//! secret, and the recipient P-256 public keys (recovery + auditor, caller
//! ordered), this builds every ciphertext the circuit verifies, recomputes the
//! public-input hash, requests a Groth16 proof from the prover server, and
//! returns the 192-byte compressed proof plus the published artifacts.

use num_bigint::BigUint;
use p256::SecretKey;
use serde::Serialize;
use zolana_keypair::{P256Pubkey, ViewingKey};

use crate::prover::{
    error::SquadsProverError,
    proof::gnark_json_to_transact_bytes,
    server::send_prove_request,
    shared_viewing_key::{
        ciphertext_hash, ecdh_encrypt, hash_chain, hash_field, pack33, secret_key_from_be,
    },
};

/// Supported recipient-key counts (recovery + auditor). MUST mirror the program's
/// `KEY_ENCRYPTION_SUPPORTED_KEYS` and the Go lazy key manager.
pub const KEY_ENCRYPTION_SUPPORTED_KEYS: [usize; 3] = [1, 2, 3];

/// Inputs to the key-encryption proof. `recipient_keys` is recovery keys first,
/// then auditor keys (the circuit treats them identically; ordering is the
/// on-chain concern, circuit.go:29).
pub struct KeyEncryptionWitness {
    /// Shared viewing secret key (a P-256 scalar). Its public key `sk·G` is the
    /// account `shared_viewing_key`; its 32-byte big-endian form is the plaintext
    /// encrypted to every recipient.
    pub viewing_secret_key: SecretKey,
    /// The single shared ephemeral secret (a full-range P-256 scalar; the
    /// circuit witnesses it as an emulated P256Fr element).
    pub ephemeral_secret_key: SecretKey,
    /// The nullifier secret (a BN254-range field element).
    pub nullifier_secret: [u8; 32],
    /// Recovery keys first, then auditor keys.
    pub recipient_keys: Vec<P256Pubkey>,
    /// Binds the proof to a prior account state on rotation; all-zero at creation.
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
    /// The 192-byte compressed Groth16 proof (BSB22 layout, commitment included).
    pub proof: [u8; 192],
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

fn fe_hex(bytes: &[u8; 32]) -> String {
    format!("0x{}", BigUint::from_bytes_be(bytes).to_str_radix(16))
}

fn byte_hex(b: u8) -> String {
    format!("0x{b:x}")
}

/// The 65-byte uncompressed SEC1 encoding (0x04 || x || y) of a P-256 pubkey.
fn uncompressed_65(pk: &P256Pubkey) -> Result<[u8; 65], SquadsProverError> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let p = pk.to_p256().map_err(|_| SquadsProverError::InvalidPubkey)?;
    let encoded = p.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    if bytes.len() != 65 {
        return Err(SquadsProverError::InvalidPubkey);
    }
    let mut out = [0u8; 65];
    out.copy_from_slice(bytes);
    Ok(out)
}

impl KeyEncryptionWitness {
    /// Build all ciphertexts and the public-input hash, then request a proof from
    /// the prover at `server_address` (e.g. `ProverClient`'s `SERVER_ADDRESS`).
    pub fn prove(
        self,
        server_address: &str,
    ) -> Result<KeyEncryptionProofResult, SquadsProverError> {
        let num_keys = self.recipient_keys.len();
        if !KEY_ENCRYPTION_SUPPORTED_KEYS.contains(&num_keys) {
            return Err(SquadsProverError::UnsupportedKeyCount(num_keys));
        }

        // Shared viewing public key sk·G and its 32-byte big-endian scalar (the
        // plaintext encrypted to every recipient). circuit.go:73-82.
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
            // dh = ECDH(eph, recipient) = x-coordinate of eph·recipient_pk.
            let dh = eph_viewing
                .ecdh(rpk)
                .map_err(|_| SquadsProverError::InvalidPubkey)?;
            let ciphertext = ecdh_encrypt(&dh, &eph_pk_comp, &rpk_comp, &viewing_sk_be)?;
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
        let nullifier_ciphertext =
            ecdh_encrypt(&dh_null, &eph_pk_comp, &shared_viewing_comp, null_plaintext)?;

        let public_input_hash = compute_public_input_hash(
            &self.old_state_hash,
            &viewing_pubkey,
            &commitment,
            &ephemeral_pubkey,
            &recipient_ciphertexts,
            &nullifier_pubkey,
            &nullifier_ciphertext,
        )?;

        // Request a proof from the server.
        let request = self.build_request(&viewing_sk_be, &public_input_hash, num_keys)?;
        let proof_json = send_prove_request(server_address, &request)?;
        let proof = gnark_json_to_transact_bytes(&proof_json)?;

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

    fn build_request(
        &self,
        viewing_sk_be: &[u8; 32],
        public_input_hash: &[u8; 32],
        num_keys: usize,
    ) -> Result<String, SquadsProverError> {
        let mut eph_be = [0u8; 32];
        eph_be.copy_from_slice(self.ephemeral_secret_key.to_bytes().as_slice());

        // The circuit's RecipientKey.Pubkey is the 65-byte UNCOMPRESSED point
        // (0x04 || x || y); it compresses in-circuit (circuit.go:104). The Go
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
            .map_err(|e| SquadsProverError::ProofParse(format!("request serialization: {e}")))
    }
}

/// Recompute the circuit's `PublicInputHash`. Chain order mirrors `Circuit.Define`
/// (circuit.go:90-118) and the program's `KeyEncryptionProof::public_input_hash`.
#[allow(clippy::too_many_arguments)]
fn compute_public_input_hash(
    old_state_hash: &[u8; 32],
    shared_viewing_pubkey: &P256Pubkey,
    commitment: &[u8; 32],
    ephemeral_pubkey: &P256Pubkey,
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

/// Build a P-256 `SecretKey` from a 32-byte big-endian scalar (for callers that
/// hold raw ephemeral/viewing scalars).
pub fn scalar_secret_key(scalar_be: &[u8; 32]) -> Result<SecretKey, SquadsProverError> {
    secret_key_from_be(scalar_be)
}
