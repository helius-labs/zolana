//! Build a fully-populated `CreateViewingKeyAccountIxData` from a key-encryption
//! proof.
//!
//! The on-chain program (`process_create_viewing_key_account_ix`) recomputes the
//! key-encryption proof's public-input hash from EXACTLY these instruction fields
//! plus the auditor key read from `zone_config`, so every field here MUST be the
//! same bytes the proof inputs used. The auditor recipient key(s)
//! are NOT in the instruction data. The program reads them from `zone_config`, so
//! the trailing auditor recipient key must equal the zone's configured
//! auditor. See [`create_viewing_key_account_ix_data`] for the recovery/auditor
//! ordering contract.

use zolana_squads_interface::{
    constants::{ENCRYPTION_SCHEME_P256_AES, OWNER_KIND_KEYPAIR},
    instruction::instruction_data::{CreateViewingKeyAccountIxData, ExecuteKeyUpdateIxData},
    types::{EncryptedNullifierSecret, P256Pubkey, SharedKeyCiphertext},
};

use crate::prover::{
    error::SquadsProverError,
    key_encryption::{KeyEncryptionProofResult, RecipientCiphertext},
    key_encryption_fold::KeyEncryptionFoldProofResult,
};

#[cfg(feature = "prover")]
use crate::prover::key_encryption::KeyEncryptionProofInputs;
#[cfg(feature = "prover")]
use crate::prover::key_encryption_fold::KeyEncryptionFoldProofInputs;
#[cfg(feature = "prover")]
use zolana_squads_interface::state::ViewingKeyAccount;

/// Convert a `KeyEncryptionProofResult` into a `CreateViewingKeyAccountIxData`.
///
/// `recovery_count` is the number of recovery (smart-account-holder) keys at the
/// FRONT of the proof's `recipient_keys`. The remainder are auditor keys whose
/// public keys live in `zone_config`. The combined `key_ciphertexts` vector keeps
/// the proof's recovery-then-auditor ordering, which is the positional contract
/// the program relies on.
///
/// Returns an error if `recovery_count` exceeds the number of recipient
/// ciphertexts, or if any ciphertext is not the expected fixed length (the
/// proof always produces 32-byte recipient ciphertexts and a 31-byte nullifier
/// ciphertext, so this only guards against a malformed result).
pub fn create_viewing_key_account_ix_data(
    result: &KeyEncryptionProofResult,
    recovery_count: usize,
) -> Result<CreateViewingKeyAccountIxData, SquadsProverError> {
    CreateAccountArtifacts {
        recipient_ciphertexts: &result.recipient_ciphertexts,
        nullifier_ciphertext: &result.nullifier_ciphertext,
        shared_viewing_key: result.shared_viewing_pubkey.as_bytes(),
        commitment: &result.commitment,
        nullifier_pubkey: &result.nullifier_pubkey,
        key_ciphertext_ephemeral: result.ephemeral_pubkey.as_bytes(),
        proof: &result.proof,
    }
    .build(recovery_count)
}

/// The same instruction data from a folded proof. A fold proves the identical
/// statement over a wider recipient set, so only the proof bytes and the
/// verifying key the program selects differ.
pub fn create_viewing_key_account_ix_data_folded(
    result: &KeyEncryptionFoldProofResult,
    recovery_count: usize,
) -> Result<CreateViewingKeyAccountIxData, SquadsProverError> {
    CreateAccountArtifacts {
        recipient_ciphertexts: &result.recipient_ciphertexts,
        nullifier_ciphertext: &result.nullifier_ciphertext,
        shared_viewing_key: result.shared_viewing_pubkey.as_bytes(),
        commitment: &result.commitment,
        nullifier_pubkey: &result.nullifier_pubkey,
        key_ciphertext_ephemeral: result.ephemeral_pubkey.as_bytes(),
        proof: &result.proof,
    }
    .build(recovery_count)
}

struct CreateAccountArtifacts<'a> {
    recipient_ciphertexts: &'a [RecipientCiphertext],
    nullifier_ciphertext: &'a [u8],
    shared_viewing_key: &'a [u8; 33],
    commitment: &'a [u8; 32],
    nullifier_pubkey: &'a [u8; 32],
    key_ciphertext_ephemeral: &'a [u8; 33],
    proof: &'a [u8; 192],
}

impl CreateAccountArtifacts<'_> {
    fn build(
        self,
        recovery_count: usize,
    ) -> Result<CreateViewingKeyAccountIxData, SquadsProverError> {
        if recovery_count > self.recipient_ciphertexts.len() {
            return Err(SquadsProverError::ProofValidation(format!(
                "recovery_count {recovery_count} exceeds {} recipient ciphertexts",
                self.recipient_ciphertexts.len()
            )));
        }

        let recovery_keys: Vec<P256Pubkey> = self
            .recipient_ciphertexts
            .iter()
            .take(recovery_count)
            .map(|rc| *rc.recipient_pubkey.as_bytes())
            .collect();

        let key_ciphertexts: Vec<SharedKeyCiphertext> = self
            .recipient_ciphertexts
            .iter()
            .map(|rc| to_shared_key_ciphertext(&rc.ciphertext))
            .collect::<Result<_, _>>()?;

        let encrypted_nullifier_secret = to_encrypted_nullifier_secret(self.nullifier_ciphertext)?;

        Ok(CreateViewingKeyAccountIxData {
            key_encryption_proof: *self.proof,
            encryption_scheme: ENCRYPTION_SCHEME_P256_AES,
            // Callers that create a smart-account viewing-key account override this
            // owner kind before building the instruction.
            owner_kind: OWNER_KIND_KEYPAIR,
            shared_viewing_key: *self.shared_viewing_key,
            shared_viewing_key_commitment: *self.commitment,
            nullifier_pubkey: *self.nullifier_pubkey,
            key_ciphertext_ephemeral: *self.key_ciphertext_ephemeral,
            encrypted_nullifier_secret,
            recovery_keys,
            key_ciphertexts,
        })
    }
}

fn to_shared_key_ciphertext(bytes: &[u8]) -> Result<SharedKeyCiphertext, SquadsProverError> {
    let arr: SharedKeyCiphertext = bytes.try_into().map_err(|_| {
        SquadsProverError::ProofValidation(format!(
            "recipient ciphertext length {} != 32",
            bytes.len()
        ))
    })?;
    Ok(arr)
}

fn to_encrypted_nullifier_secret(
    bytes: &[u8],
) -> Result<EncryptedNullifierSecret, SquadsProverError> {
    let arr: EncryptedNullifierSecret = bytes.try_into().map_err(|_| {
        SquadsProverError::ProofValidation(format!(
            "nullifier ciphertext length {} != 31",
            bytes.len()
        ))
    })?;
    Ok(arr)
}

/// Runs the key-encryption proof inputs against the prover server and returns both the
/// `CreateViewingKeyAccountIxData` and the underlying `KeyEncryptionProofResult`.
///
/// `recovery_count` is as in [`create_viewing_key_account_ix_data`].
#[cfg(feature = "prover")]
pub fn prove_create_viewing_key_account(
    proof_inputs: KeyEncryptionProofInputs,
    recovery_count: usize,
    server_address: &str,
) -> Result<(CreateViewingKeyAccountIxData, KeyEncryptionProofResult), SquadsProverError> {
    let result = proof_inputs.prove(server_address)?;
    let ix_data = create_viewing_key_account_ix_data(&result, recovery_count)?;
    Ok((ix_data, result))
}

/// The folded counterpart of [`prove_create_viewing_key_account`], for an
/// account whose recipient set is wider than any single circuit proves.
#[cfg(feature = "prover")]
pub fn prove_create_viewing_key_account_folded(
    proof_inputs: KeyEncryptionFoldProofInputs,
    recovery_count: usize,
    server_address: &str,
) -> Result<(CreateViewingKeyAccountIxData, KeyEncryptionFoldProofResult), SquadsProverError> {
    let result = proof_inputs.prove(server_address)?;
    let ix_data = create_viewing_key_account_ix_data_folded(&result, recovery_count)?;
    Ok((ix_data, result))
}

/// Convert a rotation `KeyEncryptionProofResult` into `ExecuteKeyUpdateIxData`
/// plus the recovery+auditor ciphertext buffer.
///
/// `execute_key_update` reads the new shared-key material from the instruction
/// data and the `K = R' + A` ciphertexts from the key-update proposal's filled
/// buffer (it does not carry them in instruction data). The buffer here is the
/// proof's recipient ciphertexts in their recovery-then-auditor order -- the
/// positional contract `fill_key_update` and `execute_key_update` rely on. The
/// caller fills the proposal with this buffer (via `fill_key_update`) before
/// settling with the returned instruction data.
///
/// Returns an error only if a ciphertext is not the expected fixed length (the
/// proof always produces 32-byte recipient ciphertexts and a 31-byte nullifier
/// ciphertext, so this guards only against a malformed result).
pub fn execute_key_update_ix_data(
    result: &KeyEncryptionProofResult,
) -> Result<(ExecuteKeyUpdateIxData, Vec<SharedKeyCiphertext>), SquadsProverError> {
    let buffer: Vec<SharedKeyCiphertext> = result
        .recipient_ciphertexts
        .iter()
        .map(|rc| to_shared_key_ciphertext(&rc.ciphertext))
        .collect::<Result<_, _>>()?;

    let new_encrypted_nullifier_secret =
        to_encrypted_nullifier_secret(&result.nullifier_ciphertext)?;

    let ix_data = ExecuteKeyUpdateIxData {
        rotation_proof: result.proof,
        new_shared_viewing_key: *result.shared_viewing_pubkey.as_bytes(),
        new_shared_viewing_key_commitment: result.commitment,
        new_nullifier_pubkey: result.nullifier_pubkey,
        new_key_ciphertext_ephemeral: *result.ephemeral_pubkey.as_bytes(),
        new_encrypted_nullifier_secret,
    };

    Ok((ix_data, buffer))
}

/// Runs the rotation key-encryption proof inputs against the prover server and returns
/// the `ExecuteKeyUpdateIxData`, the proposal-buffer ciphertexts (recovery then
/// auditor), and the underlying `KeyEncryptionProofResult`.
///
/// `proof_inputs.recipient_keys` MUST be the resulting recovery keys (after the
/// proposal's `operations` are applied to the target's recovery keys) followed by
/// the zone's auditor key(s). This helper replaces `proof_inputs.old_state_hash`
/// with the target account's canonical pre-rotation commitment.
#[cfg(feature = "prover")]
pub fn prove_execute_key_update(
    mut proof_inputs: KeyEncryptionProofInputs,
    target: &ViewingKeyAccount,
    server_address: &str,
) -> Result<
    (
        ExecuteKeyUpdateIxData,
        Vec<SharedKeyCiphertext>,
        KeyEncryptionProofResult,
    ),
    SquadsProverError,
> {
    proof_inputs.old_state_hash = target
        .key_rotation_commitment()
        .map_err(|_| SquadsProverError::Poseidon)?;
    let result = proof_inputs.prove(server_address)?;
    let (ix_data, buffer) = execute_key_update_ix_data(&result)?;
    Ok((ix_data, buffer, result))
}
