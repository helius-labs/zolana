//! Fold several key-encryption legs into one proof over a wider recipient set.
//!
//! The key-encryption circuit has a key for 1, 2, and 3 recipients only, while
//! a `ViewingKeyAccount` holds more. Splitting the set across legs of the widest
//! supported count and folding them lifts that cap with one ceremony.
//!
//! The folded proof's public input is the chain a single circuit over the whole
//! set would expose, so the program recomputes it exactly as it does for an
//! unfolded proof and only the verifying key differs.

use p256::SecretKey;
use serde::Serialize;
use zolana_keypair::P256Pubkey;

use crate::prover::{
    error::SquadsProverError,
    fold::{leg_json, LegJson},
    key_encryption::{
        key_encryption_public_input_chain, KeyEncryptionProofInputs, KeyEncryptionPublicInputs,
        RecipientCiphertext,
    },
    proof::gnark_json_to_transact_bytes,
    server::send_prove_request,
    shared_viewing_key::hash_chain,
};

pub use zolana_squads_interface::circuits::{
    KEY_ENCRYPTION_FOLD_KEYS_PER_LEG, KEY_ENCRYPTION_FOLD_SUPPORTED_KEYS,
    KEY_ENCRYPTION_FOLD_SUPPORTED_LEGS,
};

/// Recipients per leg, as a chunk length.
const KEYS_PER_LEG: usize = KEY_ENCRYPTION_FOLD_KEYS_PER_LEG as usize;

pub fn key_encryption_fold_supported_keys() -> impl Iterator<Item = usize> {
    KEY_ENCRYPTION_FOLD_SUPPORTED_KEYS
        .into_iter()
        .map(usize::from)
}

/// Inputs to a folded key-encryption proof. Same as the unfolded inputs except
/// `recipient_keys` must fill whole legs.
pub struct KeyEncryptionFoldProofInputs {
    pub viewing_secret_key: SecretKey,
    pub ephemeral_secret_key: SecretKey,
    pub nullifier_secret: [u8; 32],
    /// Recovery keys first, then auditor keys. Its length must be a supported
    /// leg count times [`KEY_ENCRYPTION_FOLD_KEYS_PER_LEG`].
    pub recipient_keys: Vec<P256Pubkey>,
    pub old_state_hash: [u8; 32],
}

/// The published artifacts of a folded key-encryption proof. Identical in shape
/// to the unfolded result, because the statement is the same one over a wider
/// recipient set.
pub struct KeyEncryptionFoldProofResult {
    pub old_state_hash: [u8; 32],
    pub shared_viewing_pubkey: P256Pubkey,
    pub commitment: [u8; 32],
    pub ephemeral_pubkey: P256Pubkey,
    /// Every leg's ciphertexts, in leg order, which is caller order.
    pub recipient_ciphertexts: Vec<RecipientCiphertext>,
    pub nullifier_pubkey: [u8; 32],
    pub nullifier_ciphertext: Vec<u8>,
    pub public_input_hash: [u8; 32],
    /// The 192-byte compressed Groth16 proof of the fold.
    pub proof: [u8; 192],
}

#[derive(Serialize)]
struct FoldRequestJson {
    #[serde(rename = "circuitType")]
    circuit_type: &'static str,
    #[serde(rename = "keysPerLeg")]
    keys_per_leg: u32,
    legs: Vec<LegJson>,
}

impl KeyEncryptionFoldProofInputs {
    /// Every leg is built from the same viewing, ephemeral, and nullifier
    /// secrets, which is what makes the fold's equality assertions hold. A leg
    /// stays valid on its own, so the same proofs settle an unfolded update.
    pub fn prove(
        self,
        server_address: &str,
    ) -> Result<KeyEncryptionFoldProofResult, SquadsProverError> {
        let total = self.recipient_keys.len();
        let legs = total / KEYS_PER_LEG;
        if !total.is_multiple_of(KEYS_PER_LEG)
            || !u8::try_from(legs)
                .is_ok_and(|legs| KEY_ENCRYPTION_FOLD_SUPPORTED_LEGS.contains(&legs))
        {
            return Err(SquadsProverError::UnsupportedKeyCount(total));
        }

        let mut leg_requests = Vec::with_capacity(legs);
        let mut recipient_ciphertexts = Vec::with_capacity(total);
        let mut shared = None;

        for chunk in self.recipient_keys.chunks(KEYS_PER_LEG) {
            let leg = KeyEncryptionProofInputs {
                viewing_secret_key: self.viewing_secret_key.clone(),
                ephemeral_secret_key: self.ephemeral_secret_key.clone(),
                nullifier_secret: self.nullifier_secret,
                recipient_keys: chunk.to_vec(),
                old_state_hash: self.old_state_hash,
            }
            .prove(server_address)?;

            leg_requests.push(leg_json(&leg.recursion_proof, &leg.public_input_chain));
            recipient_ciphertexts.extend(leg.recipient_ciphertexts);
            if shared.is_none() {
                shared = Some((
                    leg.shared_viewing_pubkey,
                    leg.commitment,
                    leg.ephemeral_pubkey,
                    leg.nullifier_pubkey,
                    leg.nullifier_ciphertext,
                ));
            }
        }

        let (
            shared_viewing_pubkey,
            commitment,
            ephemeral_pubkey,
            nullifier_pubkey,
            nullifier_ciphertext,
        ) = shared.ok_or(SquadsProverError::UnsupportedKeyCount(total))?;

        let public_input_hash = hash_chain(&key_encryption_public_input_chain(
            KeyEncryptionPublicInputs {
                old_state_hash: &self.old_state_hash,
                shared_viewing_pubkey: &shared_viewing_pubkey,
                commitment: &commitment,
                ephemeral_pubkey: &ephemeral_pubkey,
                recipient_ciphertexts: &recipient_ciphertexts,
                nullifier_pubkey: &nullifier_pubkey,
                nullifier_ciphertext: &nullifier_ciphertext,
            },
        )?)?;

        let request = serde_json::to_string(&FoldRequestJson {
            circuit_type: "squads-key-encryption-fold",
            keys_per_leg: u32::from(KEY_ENCRYPTION_FOLD_KEYS_PER_LEG),
            legs: leg_requests,
        })
        .map_err(|e| SquadsProverError::RequestSerialize(format!("{e}")))?;
        let proof_json = send_prove_request(server_address, &request)?;
        let proof = gnark_json_to_transact_bytes(&proof_json)?;

        Ok(KeyEncryptionFoldProofResult {
            old_state_hash: self.old_state_hash,
            shared_viewing_pubkey,
            commitment,
            ephemeral_pubkey,
            recipient_ciphertexts,
            nullifier_pubkey,
            nullifier_ciphertext,
            public_input_hash,
            proof,
        })
    }
}
