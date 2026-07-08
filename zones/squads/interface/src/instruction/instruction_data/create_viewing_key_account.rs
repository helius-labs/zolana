//! `create_viewing_key_account` (tag 5) instruction data (spec: squads
//! `create_viewing_key_account`).

use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use crate::types::{EncryptedNullifierSecret, P256Pubkey, ProofBytes, SharedKeyCiphertext};

/// `create_viewing_key_account` instruction data (spec: squads
/// `create_viewing_key_account`).
///
/// Carries the key encryption proof (`old_state_hash = 0`) plus the new key
/// material written into the viewing key account: the public shared viewing key
/// and its commitment, the shared ephemeral key, the nullifier commitment and
/// the nullifier secret encrypted to the shared viewing key, the recovery keys,
/// and the per-key ciphertexts (recovery keys first, then the auditor). The
/// auditor key itself is read from `zone_config`, not instruction data.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateViewingKeyAccountIxData {
    /// Compressed Groth16 key encryption proof with commitment.
    pub key_encryption_proof: ProofBytes,
    /// Encryption scheme for the shared key and UTXO ciphertexts.
    pub encryption_scheme: u8,
    /// Owner kind written into the viewing key account: `OWNER_KIND_KEYPAIR`
    /// (P256 rail) or `OWNER_KIND_SMART_ACCOUNT` (signatureless vault rail).
    pub owner_kind: u8,
    /// Public shared viewing key.
    pub shared_viewing_key: P256Pubkey,
    /// Poseidon commitment to the shared viewing secret key.
    pub shared_viewing_key_commitment: [u8; 32],
    /// Nullifier commitment.
    pub nullifier_pubkey: [u8; 32],
    /// Ephemeral P-256 key shared by every shared-key ciphertext below.
    pub key_ciphertext_ephemeral: P256Pubkey,
    /// Nullifier secret AES-CTR-encrypted to the shared viewing key using
    /// `key_ciphertext_ephemeral`.
    pub encrypted_nullifier_secret: EncryptedNullifierSecret,
    /// Smart account holder keys; empty for an auditor-only account.
    #[wincode(with = "containers::Vec<[u8; 33], FixIntLen<u8>>")]
    pub recovery_keys: Vec<P256Pubkey>,
    /// Shared private key encrypted to each recovery key, then the auditor.
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub key_ciphertexts: Vec<SharedKeyCiphertext>,
}

impl CreateViewingKeyAccountIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
