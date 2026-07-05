//! `execute_key_update` (tag 14) instruction data (spec: squads
//! `execute_key_update`).

use wincode::{SchemaRead, SchemaWrite};

use crate::types::{EncryptedNullifierSecret, P256Pubkey, ProofBytes};

/// `execute_key_update` instruction data (spec: squads `execute_key_update`).
///
/// Settles an approved key update proposal with the key encryption (rotation)
/// proof. The new recovery and auditor ciphertexts come from the proposal
/// buffer, so they are not carried here; the executor supplies the new shared
/// key material and the re-encrypted nullifier secret. Constant size in the key
/// count by design.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ExecuteKeyUpdateIxData {
    /// Compressed Groth16 key encryption proof with commitment.
    pub rotation_proof: ProofBytes,
    /// New public shared viewing key.
    pub new_shared_viewing_key: P256Pubkey,
    /// Poseidon commitment to the new shared viewing secret key.
    pub new_shared_viewing_key_commitment: [u8; 32],
    /// Fresh nullifier commitment for this rotation.
    pub new_nullifier_pubkey: [u8; 32],
    /// Ephemeral P-256 key shared by the buffered recovery and auditor
    /// ciphertexts and `new_encrypted_nullifier_secret`.
    pub new_key_ciphertext_ephemeral: P256Pubkey,
    /// New random nullifier secret AES-CTR-encrypted to the new shared viewing
    /// key using `new_key_ciphertext_ephemeral`.
    pub new_encrypted_nullifier_secret: EncryptedNullifierSecret,
}

impl ExecuteKeyUpdateIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
