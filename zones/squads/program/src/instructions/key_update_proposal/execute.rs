//! `execute_key_update` (tag 14): settle a fully filled key-update proposal,
//! verifying the key-encryption (rotation) proof and applying the rotation to the
//! target viewing key account.

use pinocchio::{
    sysvars::{rent::Rent, Sysvar},
    AccountView, ProgramResult, Resize,
};
use zolana_squads_interface::{
    constants::{
        KEY_OP_ADD, KEY_OP_REMOVE, KEY_OP_REPLACE, KEY_OP_UPDATE_AUDITOR,
        REQUIRED_AUDITOR_KEY_COUNT,
    },
    error::SquadsZoneError,
    instruction::instruction_data::ExecuteKeyUpdateIxData,
    state::{key_update_proposal::KeyOperation, viewing_key_account::ViewingKeyAccount},
};

use super::loader::load_key_update_proposal;
use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::instructions::zone_config::loader::load_zone_config;
use crate::shared::{
    close::close_account,
    key_encryption_proof::{KeyEncryptionProof, RecipientKey},
};

/// Apply `operations` to a copy of `recovery_keys`, returning the resulting
/// recovery list `R'`. ADD appends `op.key`, REMOVE drops the entry at
/// `op.index`, REPLACE overwrites `op.index` with `op.key`; the auditor-update op
/// leaves the recovery list unchanged. Indices are bound-checked against the
/// evolving list.
#[inline(never)]
fn apply_recovery_operations(
    operations: &[KeyOperation],
    recovery_keys: &[[u8; 33]],
) -> Result<Vec<[u8; 33]>, SquadsZoneError> {
    let mut updated_recovery_keys = recovery_keys.to_vec();
    for op in operations {
        match op.op {
            KEY_OP_UPDATE_AUDITOR => {
                // Recovery list unchanged.
            }
            KEY_OP_ADD => updated_recovery_keys.push(op.key),
            KEY_OP_REMOVE => {
                let index = op.index as usize;
                if index >= updated_recovery_keys.len() {
                    return Err(SquadsZoneError::InvalidKeyOperationIndex);
                }
                updated_recovery_keys.remove(index);
            }
            KEY_OP_REPLACE => {
                let slot = updated_recovery_keys
                    .get_mut(op.index as usize)
                    .ok_or(SquadsZoneError::InvalidKeyOperationIndex)?;
                *slot = op.key;
            }
            _ => return Err(SquadsZoneError::InvalidKeyOperation),
        }
    }
    Ok(updated_recovery_keys)
}

/// `execute_key_update` (tag 14): settle a fully filled key-update proposal,
/// verifying the key-encryption (rotation) proof and applying the rotation to the
/// target viewing key account.
///
/// Accounts: `[executor (signer, writable, fee payer), co_signer (signer),
/// viewing_key_account (writable, target), zone_config (readonly),
/// key_update_proposal (writable), rent_recipient (writable), system_program
/// (readonly)]`.
#[inline(never)]
pub fn process_execute_key_update_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < 7 {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    }
    let (executor, rest) = accounts
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (co_signer, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (viewing_key_account, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (zone_config, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (key_update_proposal, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let rent_recipient = rest
        .first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;

    if !executor.is_signer() {
        return Err(SquadsZoneError::MissingExecutorSignature.into());
    }
    if !co_signer.is_signer() {
        return Err(SquadsZoneError::MissingCoSignerSignature.into());
    }

    let proposal = load_key_update_proposal(key_update_proposal)?;
    let zone = load_zone_config(zone_config)?;
    let target_vka = load_viewing_key_account(viewing_key_account)?;

    if executor.address() != &proposal.executor {
        return Err(SquadsZoneError::ExecutorMismatch.into());
    }
    if co_signer.address() != &zone.co_signer {
        return Err(SquadsZoneError::CoSignerMismatch.into());
    }
    if rent_recipient.address() != &proposal.rent_payer {
        return Err(SquadsZoneError::RentRecipientMismatch.into());
    }

    let ix = ExecuteKeyUpdateIxData::deserialize(data)
        .map_err(|_| SquadsZoneError::InvalidInstructionData)?;

    if zone.auditor_keys.len() != REQUIRED_AUDITOR_KEY_COUNT {
        return Err(SquadsZoneError::InvalidAuditorKeyCount.into());
    }

    // Apply the proposal's operations to the target's recovery keys to get R'.
    let resulting_recovery =
        apply_recovery_operations(&proposal.operations, &target_vka.recovery_keys)?;
    let recovery_count = resulting_recovery.len();
    let auditor_count = zone.auditor_keys.len();

    // The buffer must be fully filled: K = R' + A.
    let buffer_capacity = recovery_count
        .checked_add(auditor_count)
        .ok_or(SquadsZoneError::ArithmeticOverflow)?;
    if proposal.new_key_ciphertexts.len() != buffer_capacity {
        return Err(SquadsZoneError::KeyBufferNotFull.into());
    }

    // Buffer ordering is recovery ciphertexts first, then auditor (positional
    // contract with the prover; see key_encryption_proof).
    let (recovery_ciphertexts, auditor_ciphertexts) =
        proposal.new_key_ciphertexts.split_at(recovery_count);

    // Build the proof's recipient keys: resulting recovery keys then auditor
    // keys, each paired with its ciphertext in the same recovery-then-auditor
    // order.
    let mut recipient_keys: Vec<RecipientKey> = Vec::with_capacity(buffer_capacity);
    for (rpk, ciphertext) in resulting_recovery.iter().zip(recovery_ciphertexts.iter()) {
        recipient_keys.push(RecipientKey {
            rpk,
            ciphertext: ciphertext.as_slice(),
        });
    }
    for (rpk, ciphertext) in zone.auditor_keys.iter().zip(auditor_ciphertexts.iter()) {
        recipient_keys.push(RecipientKey {
            rpk,
            ciphertext: ciphertext.as_slice(),
        });
    }

    // PROVISIONAL(old-state-hash): the rotation proof is currently verified with
    // old_state_hash=0; pass the pre-rotation viewing-key-account state hash when
    // the circuit's old_state_hash derivation is confirmed.
    KeyEncryptionProof {
        old_state_hash: [0u8; 32],
        shared_pk: &ix.new_shared_viewing_key,
        commitment: ix.new_shared_viewing_key_commitment,
        eph_pk: &ix.new_key_ciphertext_ephemeral,
        recipient_keys: &recipient_keys,
        nullifier_pubkey: ix.new_nullifier_pubkey,
        nullifier_ciphertext: ix.new_encrypted_nullifier_secret.as_slice(),
        proof: &ix.rotation_proof,
    }
    .verify()?;

    // TODO(self-cpi-event): record the complete pre-rotation viewing key account
    // as a self-CPI event (spec) so indexers retain the old keys for decrypting
    // pre-rotation balances; out of scope here.

    // Build the rotated viewing key account.
    let key_nonce = target_vka
        .key_nonce
        .checked_add(1)
        .ok_or(SquadsZoneError::ArithmeticOverflow)?;
    let rotated = ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: target_vka.owner,
        state: target_vka.state,
        encryption_scheme: target_vka.encryption_scheme,
        owner_kind: target_vka.owner_kind,
        shared_viewing_key: ix.new_shared_viewing_key,
        shared_viewing_key_commitment: ix.new_shared_viewing_key_commitment,
        key_nonce,
        nullifier_pubkey: ix.new_nullifier_pubkey,
        key_ciphertext_ephemeral: ix.new_key_ciphertext_ephemeral,
        encrypted_nullifier_secret: ix.new_encrypted_nullifier_secret,
        recovery_keys: resulting_recovery,
        recovery_key_ciphertexts: recovery_ciphertexts.to_vec(),
        auditor_keys: zone.auditor_keys.clone(),
        auditor_key_ciphertexts: auditor_ciphertexts.to_vec(),
    };
    let bytes = rotated
        .serialize()
        .map_err(|_| SquadsZoneError::Deserialization)?;

    // The VKA size may change (recovery count changed). This instruction's
    // account set has no fee payer/system program to fund a rent top-up, so a
    // grow must already be covered by the current balance; a shrink keeps it
    // (over-funded) rent-exempt (mirrors `zone_config::update`).
    if bytes.len() != viewing_key_account.data_len() {
        if bytes.len() > viewing_key_account.data_len() {
            let required = Rent::get()?.try_minimum_balance(bytes.len())?;
            if viewing_key_account.lamports() < required {
                return Err(SquadsZoneError::InvalidAccountSize.into());
            }
        }
        viewing_key_account
            .resize(bytes.len())
            .map_err(|_| SquadsZoneError::InvalidAccountSize)?;
    }
    {
        let mut account_data = viewing_key_account
            .try_borrow_mut()
            .map_err(|_| SquadsZoneError::InvalidViewingKeyAccount)?;
        let slot = account_data
            .get_mut(..bytes.len())
            .ok_or(SquadsZoneError::InvalidAccountSize)?;
        slot.copy_from_slice(&bytes);
    }

    // Close the settled proposal, refunding rent to the recorded rent payer.
    close_account(
        key_update_proposal,
        rent_recipient,
        SquadsZoneError::InvalidKeyUpdateProposal,
    )
}
