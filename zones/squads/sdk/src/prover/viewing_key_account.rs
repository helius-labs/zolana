//! Build a fully-populated `CreateViewingKeyAccountIxData` from a key-encryption
//! proof.
//!
//! The on-chain program (`process_create_viewing_key_account_ix`) recomputes the
//! key-encryption proof's public-input hash from EXACTLY these instruction fields
//! plus the auditor key read from `zone_config`, so every field here MUST be the
//! same bytes the witness used to produce the proof. The witness's
//! `recipient_keys` are caller-ordered recovery keys first, then auditor keys;
//! `KeyEncryptionProofResult::recipient_ciphertexts` preserves that order. We
//! therefore split the recipient list at `recovery_count`: the first
//! `recovery_count` entries are the recovery keys (written into `recovery_keys`),
//! and the full ciphertext list (recovery then auditor) becomes `key_ciphertexts`.
//! The auditor recipient key(s) are NOT placed in the instruction data; the
//! program supplies them from `zone_config`, so the caller must ensure the
//! witness's trailing auditor recipient key equals the zone's configured auditor.

use zolana_squads_interface::{
    constants::{ENCRYPTION_SCHEME_P256_AES, OWNER_KIND_KEYPAIR},
    instruction::instruction_data::{CreateViewingKeyAccountIxData, ExecuteKeyUpdateIxData},
    types::{EncryptedNullifierSecret, P256Pubkey, SharedKeyCiphertext},
};

use crate::prover::{error::SquadsProverError, key_encryption::KeyEncryptionProofResult};

#[cfg(feature = "prover")]
use crate::prover::key_encryption::KeyEncryptionWitness;

/// Convert a `KeyEncryptionProofResult` into a `CreateViewingKeyAccountIxData`.
///
/// `recovery_count` is the number of recovery (smart-account-holder) keys at the
/// FRONT of the witness's `recipient_keys`; the remainder are auditor keys whose
/// public keys live in `zone_config`. The combined `key_ciphertexts` vector keeps
/// the witness's recovery-then-auditor ordering, which is the positional contract
/// the program relies on.
///
/// Returns an error if `recovery_count` exceeds the number of recipient
/// ciphertexts, or if any ciphertext is not the expected fixed length (the
/// witness always produces 32-byte recipient ciphertexts and a 31-byte nullifier
/// ciphertext, so this only guards against a malformed result).
pub fn create_viewing_key_account_ix_data(
    result: &KeyEncryptionProofResult,
    recovery_count: usize,
) -> Result<CreateViewingKeyAccountIxData, SquadsProverError> {
    if recovery_count > result.recipient_ciphertexts.len() {
        return Err(SquadsProverError::ProofParse(format!(
            "recovery_count {recovery_count} exceeds {} recipient ciphertexts",
            result.recipient_ciphertexts.len()
        )));
    }

    // Recovery keys are the first `recovery_count` recipient public keys.
    let recovery_keys: Vec<P256Pubkey> = result
        .recipient_ciphertexts
        .iter()
        .take(recovery_count)
        .map(|rc| *rc.recipient_pubkey.as_bytes())
        .collect();

    // Combined ciphertexts in witness order: recovery first, then auditor.
    let key_ciphertexts: Vec<SharedKeyCiphertext> = result
        .recipient_ciphertexts
        .iter()
        .map(|rc| to_shared_key_ciphertext(&rc.ciphertext))
        .collect::<Result<_, _>>()?;

    let encrypted_nullifier_secret = to_encrypted_nullifier_secret(&result.nullifier_ciphertext)?;

    Ok(CreateViewingKeyAccountIxData {
        key_encryption_proof: result.proof,
        encryption_scheme: ENCRYPTION_SCHEME_P256_AES,
        // Default owner kind; callers that create a smart-account viewing key
        // account override this field before building the instruction.
        owner_kind: OWNER_KIND_KEYPAIR,
        shared_viewing_key: *result.shared_viewing_pubkey.as_bytes(),
        shared_viewing_key_commitment: result.commitment,
        nullifier_pubkey: result.nullifier_pubkey,
        key_ciphertext_ephemeral: *result.ephemeral_pubkey.as_bytes(),
        encrypted_nullifier_secret,
        recovery_keys,
        key_ciphertexts,
    })
}

fn to_shared_key_ciphertext(bytes: &[u8]) -> Result<SharedKeyCiphertext, SquadsProverError> {
    let arr: SharedKeyCiphertext = bytes.try_into().map_err(|_| {
        SquadsProverError::ProofParse(format!("recipient ciphertext length {} != 32", bytes.len()))
    })?;
    Ok(arr)
}

fn to_encrypted_nullifier_secret(
    bytes: &[u8],
) -> Result<EncryptedNullifierSecret, SquadsProverError> {
    let arr: EncryptedNullifierSecret = bytes.try_into().map_err(|_| {
        SquadsProverError::ProofParse(format!("nullifier ciphertext length {} != 31", bytes.len()))
    })?;
    Ok(arr)
}

/// Convenience: run the key-encryption witness against the prover server and
/// return both the `CreateViewingKeyAccountIxData` and the underlying
/// `KeyEncryptionProofResult` (so callers can inspect the published artifacts).
///
/// `recovery_count` is the number of recovery keys at the front of the witness's
/// `recipient_keys`; the trailing keys are auditors and MUST match the zone
/// config's auditor keys for on-chain verification to succeed.
#[cfg(feature = "prover")]
pub fn prove_create_viewing_key_account(
    witness: KeyEncryptionWitness,
    recovery_count: usize,
    server_address: &str,
) -> Result<(CreateViewingKeyAccountIxData, KeyEncryptionProofResult), SquadsProverError> {
    let result = witness.prove(server_address)?;
    let ix_data = create_viewing_key_account_ix_data(&result, recovery_count)?;
    Ok((ix_data, result))
}

/// Convert a rotation `KeyEncryptionProofResult` into `ExecuteKeyUpdateIxData`
/// plus the recovery+auditor ciphertext buffer.
///
/// `execute_key_update` reads the new shared-key material from the instruction
/// data and the `K = R' + A` ciphertexts from the key-update proposal's filled
/// buffer (it does not carry them in instruction data). The buffer here is the
/// witness's recipient ciphertexts in their recovery-then-auditor order -- the
/// positional contract `fill_key_update` and `execute_key_update` rely on. The
/// caller fills the proposal with this buffer (via `fill_key_update`) before
/// settling with the returned instruction data.
///
/// Returns an error only if a ciphertext is not the expected fixed length (the
/// witness always produces 32-byte recipient ciphertexts and a 31-byte nullifier
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

/// Convenience: run the rotation key-encryption witness against the prover server
/// and return the `ExecuteKeyUpdateIxData`, the proposal-buffer ciphertexts
/// (recovery then auditor), and the underlying `KeyEncryptionProofResult`.
///
/// `witness.recipient_keys` MUST be the resulting recovery keys (after the
/// proposal's `operations` are applied to the target's recovery keys) followed by
/// the zone's auditor key(s); `witness.old_state_hash` MUST be `[0u8; 32]`, matching
/// the value `execute_key_update` currently passes to the proof.
#[cfg(feature = "prover")]
pub fn prove_execute_key_update(
    witness: KeyEncryptionWitness,
    server_address: &str,
) -> Result<
    (
        ExecuteKeyUpdateIxData,
        Vec<SharedKeyCiphertext>,
        KeyEncryptionProofResult,
    ),
    SquadsProverError,
> {
    let result = witness.prove(server_address)?;
    let (ix_data, buffer) = execute_key_update_ix_data(&result)?;
    Ok((ix_data, buffer, result))
}
