//! `execute_key_update` (tag 14): settle a fully filled key-update proposal,
//! verifying the key-encryption (rotation) proof and applying the rotation to the
//! target viewing key account.

use pinocchio::{
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    AccountView, ProgramResult, Resize,
};
use zolana_squads_interface::{
    constants::{
        KEY_OP_ADD, KEY_OP_REMOVE, KEY_OP_REPLACE, KEY_OP_UPDATE_AUDITOR,
        REQUIRED_AUDITOR_KEY_COUNT,
    },
    error::SquadsZoneError,
    event::KeyRotationEvent,
    instruction::instruction_data::ExecuteKeyUpdateIxData,
    state::{key_update_proposal::KeyOperation, viewing_key_account::ViewingKeyAccount},
    types::Address,
};

use super::loader::load_key_update_proposal;
use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::instructions::zone_config::loader::load_zone_config;
use crate::shared::{
    close::close_account,
    event::{emit_key_rotation_event, validate_zone_program},
    key_encryption_proof::{KeyEncryptionProof, RecipientKey},
};

/// Validate the versioned operation policy and report whether the proposal
/// declares the auditor update. Auditor-only and recipient-preserving rotations
/// are supported. Recovery set changes stay disabled until an
/// owner-authenticated instruction exists, so the recovery list never changes.
#[inline(never)]
fn declares_auditor_update(operations: &[KeyOperation]) -> Result<bool, SquadsZoneError> {
    let mut auditor_update = false;
    for op in operations {
        match op.op {
            KEY_OP_UPDATE_AUDITOR => auditor_update = true,
            // Creation rejects recovery-set changes in this instruction
            // version. Keep the same gate at execution so proposals created
            // before an upgrade cannot bypass the new authorization policy.
            KEY_OP_ADD | KEY_OP_REMOVE | KEY_OP_REPLACE => {
                return Err(SquadsZoneError::RecoveryKeyUpdateUnsupported)
            }
            _ => return Err(SquadsZoneError::InvalidKeyOperation),
        }
    }
    Ok(auditor_update)
}

/// Accounts: `[executor (signer, writable, fee payer), co_signer (signer),
/// viewing_key_account (writable, target), zone_config (readonly),
/// key_update_proposal (writable), rent_recipient (writable), system_program
/// (readonly)]`.
#[inline(never)]
pub fn process_execute_key_update_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < 8 {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    }
    validate_zone_program(&accounts[7])?;
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
    // A blocked account is still rotated. Blocking is the response to a
    // suspected key compromise and the rotation is the remedy for it.
    let target_vka = load_viewing_key_account(viewing_key_account)?;

    if proposal.target != *viewing_key_account.address() {
        return Err(SquadsZoneError::ProposalTargetMismatch.into());
    }
    // A rotation advances the nonce, so a proposal opened before it no longer
    // describes the account it would settle against.
    if proposal.key_nonce != target_vka.key_nonce {
        return Err(SquadsZoneError::StaleKeyUpdateProposal.into());
    }
    if executor.address() != &proposal.executor {
        return Err(SquadsZoneError::ExecutorMismatch.into());
    }
    if co_signer.address() != &zone.co_signer {
        return Err(SquadsZoneError::CoSignerMismatch.into());
    }
    if rent_recipient.address() != &proposal.rent_payer {
        return Err(SquadsZoneError::RentRecipientMismatch.into());
    }
    if Clock::get()?.unix_timestamp > proposal.expiry {
        return Err(SquadsZoneError::ProposalExpired.into());
    }

    let ix = ExecuteKeyUpdateIxData::deserialize(data)
        .map_err(|_| SquadsZoneError::InvalidInstructionData)?;

    // A UTXO binds its owner as a hash over the nullifier public key and the
    // spend proof binds the value the account holds now. Changing it on a
    // rotation makes every pre-rotation UTXO of this account unspendable, so a
    // rotation re-encrypts the same nullifier secret and keeps the key.
    if ix.new_nullifier_pubkey != target_vka.nullifier_pubkey {
        return Err(SquadsZoneError::NullifierPubkeyRotationUnsupported.into());
    }

    // Only a proposal that declared the auditor operation adopts the zone's
    // auditor keys. Creation gates that operation behind the co-signer, so an
    // unconditional copy here would let any ungated rotation swap the auditor.
    let auditor_keys = if declares_auditor_update(&proposal.operations)? {
        zone.auditor_keys
    } else {
        target_vka.auditor_keys.clone()
    };
    if auditor_keys.len() != REQUIRED_AUDITOR_KEY_COUNT {
        return Err(SquadsZoneError::InvalidAuditorKeyCount.into());
    }

    let resulting_recovery = target_vka.recovery_keys.clone();
    let recovery_count = resulting_recovery.len();
    let auditor_count = auditor_keys.len();

    // The buffer must hold one ciphertext per resulting recovery key plus one
    // per auditor.
    let buffer_capacity = recovery_count
        .checked_add(auditor_count)
        .ok_or(SquadsZoneError::ArithmeticOverflow)?;
    if proposal.new_key_ciphertexts.len() != buffer_capacity {
        return Err(SquadsZoneError::KeyBufferNotFull.into());
    }

    // Buffer ordering is recovery ciphertexts first, then auditor (positional
    // contract with the prover, see key_encryption_proof).
    let (recovery_ciphertexts, auditor_ciphertexts) =
        proposal.new_key_ciphertexts.split_at(recovery_count);

    let mut recipient_keys: Vec<RecipientKey> = Vec::with_capacity(buffer_capacity);
    for (rpk, ciphertext) in resulting_recovery.iter().zip(recovery_ciphertexts.iter()) {
        recipient_keys.push(RecipientKey {
            rpk,
            ciphertext: ciphertext.as_slice(),
        });
    }
    for (rpk, ciphertext) in auditor_keys.iter().zip(auditor_ciphertexts.iter()) {
        recipient_keys.push(RecipientKey {
            rpk,
            ciphertext: ciphertext.as_slice(),
        });
    }

    let old_state_hash = target_vka
        .key_rotation_commitment()
        .map_err(|_| SquadsZoneError::ProofHashingFailed)?;
    KeyEncryptionProof {
        old_state_hash,
        shared_pk: &ix.new_shared_viewing_key,
        commitment: ix.new_shared_viewing_key_commitment,
        eph_pk: &ix.new_key_ciphertext_ephemeral,
        recipient_keys: &recipient_keys,
        nullifier_pubkey: target_vka.nullifier_pubkey,
        nullifier_ciphertext: ix.new_encrypted_nullifier_secret.as_slice(),
        proof: &ix.rotation_proof,
    }
    .verify()?;

    let key_nonce = target_vka
        .key_nonce
        .checked_add(1)
        .ok_or(SquadsZoneError::ArithmeticOverflow)?;

    // The rotation overwrites the shared viewing key, its commitment and every
    // recovery/auditor ciphertext, while the UTXO ciphertexts they decrypt stay
    // on chain. Record the state before it is gone, or a key holder that was
    // offline across the rotation loses every pre-rotation balance.
    emit_key_rotation_event(&KeyRotationEvent {
        account: Address::new_from_array(viewing_key_account.address().to_bytes()),
        old_state_hash,
        new_key_nonce: key_nonce,
        old_state: target_vka.clone(),
    })?;
    let rotated = ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: target_vka.owner,
        state: target_vka.state,
        encryption_scheme: target_vka.encryption_scheme,
        owner_kind: target_vka.owner_kind,
        shared_viewing_key: ix.new_shared_viewing_key,
        shared_viewing_key_commitment: ix.new_shared_viewing_key_commitment,
        key_nonce,
        nullifier_pubkey: target_vka.nullifier_pubkey,
        key_ciphertext_ephemeral: ix.new_key_ciphertext_ephemeral,
        encrypted_nullifier_secret: ix.new_encrypted_nullifier_secret,
        recovery_keys: resulting_recovery,
        recovery_key_ciphertexts: recovery_ciphertexts.to_vec(),
        auditor_keys,
        auditor_key_ciphertexts: auditor_ciphertexts.to_vec(),
    };
    let bytes = rotated
        .serialize()
        .map_err(|_| SquadsZoneError::Serialization)?;

    // The VKA size may change with the recovery count. This instruction's
    // account set has no fee payer or system program to fund a rent top-up, so
    // a grow must already be covered by the current balance. A shrink keeps
    // the account rent-exempt.
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

    close_account(
        key_update_proposal,
        rent_recipient,
        SquadsZoneError::InvalidKeyUpdateProposal,
    )
}
