use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_squads_interface::{
    constants::{ENCRYPTION_SCHEME_P256_AES, REQUIRED_AUDITOR_KEY_COUNT, VIEWING_KEY_STATE_ACTIVE},
    error::SquadsZoneError,
    instruction::instruction_data::CreateViewingKeyAccountIxData,
    state::viewing_key_account::{OwnerKind, ViewingKeyAccount},
    VIEWING_KEY_ACCOUNT_PDA_SEED,
};

use crate::instructions::zone_config::loader::load_zone_config;
use crate::shared::{
    key_encryption_proof::{KeyEncryptionProof, RecipientKey},
    pda::{verify_pda, CreatePdaAccount},
};

/// `create_viewing_key_account` (tag 5): verify the KEY-ENCRYPTION proof and
/// initialize the per-owner viewing key account PDA.
///
/// Accounts: `[enrollment_authority (signer, writable), owner_identity,
/// viewing_key_account (writable, the PDA), zone_config (readonly),
/// system_program]`.
///
/// `enrollment_authority` must be the configured zone co-signer and pays rent.
/// `owner_identity` is an already-derived proof identity field, not a signable
/// Solana key in the normal SDK flow. It is copied verbatim into the account and
/// used as the PDA seed. If recovery keys are supplied, however, the account at
/// that exact identity must be a transaction signer. Derived identities
/// therefore fail closed until a versioned instruction can bind a separate
/// owner authority. The instruction carries a combined `key_ciphertexts` vector
/// ordered recovery ciphertexts first, then auditor. The recipient public keys
/// are the instruction's `recovery_keys` followed by the auditor keys read from
/// `zone_config`. The proof is recomputed over `old_state_hash = 0` (creation).
#[inline(never)]
pub fn process_create_viewing_key_account_ix(
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 5 {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    }
    let (enrollment_authority, rest) = accounts
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (owner_identity, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (viewing_key_account, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (zone_config, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let system_program = rest
        .first()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;

    if !enrollment_authority.is_signer() {
        return Err(SquadsZoneError::MissingCoSignerSignature.into());
    }
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }

    let ix = CreateViewingKeyAccountIxData::deserialize(data)
        .map_err(|_| SquadsZoneError::InvalidInstructionData)?;

    if ix.encryption_scheme != ENCRYPTION_SCHEME_P256_AES {
        return Err(SquadsZoneError::InvalidEncryptionScheme.into());
    }

    // Reject an unknown byte at creation so the stored value always parses.
    OwnerKind::try_from(ix.owner_kind)?;

    // A zone co-signer authenticates enrollment but must not be able to grant
    // arbitrary recovery-key holders access to the owner's secrets. Require
    // control of the exact stored identity before accepting any non-auditor key.
    if !ix.recovery_keys.is_empty() && !owner_identity.is_signer() {
        return Err(SquadsZoneError::MissingOwnerSignature.into());
    }

    let zone_config = load_zone_config(zone_config)?;
    if enrollment_authority.address() != &zone_config.co_signer {
        return Err(SquadsZoneError::CoSignerMismatch.into());
    }
    if zone_config.auditor_keys.len() != REQUIRED_AUDITOR_KEY_COUNT {
        return Err(SquadsZoneError::InvalidAuditorKeyCount.into());
    }
    let auditor_keys = zone_config.auditor_keys;

    let recovery_count = ix.recovery_keys.len();
    let auditor_count = auditor_keys.len();
    let expected_ciphertexts = recovery_count
        .checked_add(auditor_count)
        .ok_or(SquadsZoneError::CiphertextCountMismatch)?;
    if ix.key_ciphertexts.len() != expected_ciphertexts {
        return Err(SquadsZoneError::CiphertextCountMismatch.into());
    }
    let (recovery_key_ciphertexts, auditor_key_ciphertexts) =
        ix.key_ciphertexts.split_at(recovery_count);

    // Recovery keys first, then auditor keys, each paired with its ciphertext in
    // the same order (circuit.go:101).
    let mut recipient_keys: Vec<RecipientKey> = Vec::with_capacity(expected_ciphertexts);
    for (rpk, ciphertext) in ix.recovery_keys.iter().zip(recovery_key_ciphertexts.iter()) {
        recipient_keys.push(RecipientKey {
            rpk,
            ciphertext: ciphertext.as_slice(),
        });
    }
    for (rpk, ciphertext) in auditor_keys.iter().zip(auditor_key_ciphertexts.iter()) {
        recipient_keys.push(RecipientKey {
            rpk,
            ciphertext: ciphertext.as_slice(),
        });
    }

    KeyEncryptionProof {
        old_state_hash: [0u8; 32],
        shared_pk: &ix.shared_viewing_key,
        commitment: ix.shared_viewing_key_commitment,
        eph_pk: &ix.key_ciphertext_ephemeral,
        recipient_keys: &recipient_keys,
        nullifier_pubkey: ix.nullifier_pubkey,
        nullifier_ciphertext: ix.encrypted_nullifier_secret.as_slice(),
        proof: &ix.key_encryption_proof,
    }
    .verify()?;

    // The owner identity is a proof field, not a signing authority. Preserve it
    // exactly: hashing it again would produce an incompatible owner and PDA.
    let owner_identity = *owner_identity.address();

    let bump = verify_pda(
        viewing_key_account.address(),
        &[VIEWING_KEY_ACCOUNT_PDA_SEED, owner_identity.as_ref()],
        &crate::ID,
    )?;

    let account = ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: owner_identity,
        state: VIEWING_KEY_STATE_ACTIVE,
        encryption_scheme: ix.encryption_scheme,
        owner_kind: ix.owner_kind,
        shared_viewing_key: ix.shared_viewing_key,
        shared_viewing_key_commitment: ix.shared_viewing_key_commitment,
        key_nonce: 0,
        nullifier_pubkey: ix.nullifier_pubkey,
        key_ciphertext_ephemeral: ix.key_ciphertext_ephemeral,
        encrypted_nullifier_secret: ix.encrypted_nullifier_secret,
        recovery_keys: ix.recovery_keys,
        recovery_key_ciphertexts: recovery_key_ciphertexts.to_vec(),
        auditor_keys,
        auditor_key_ciphertexts: auditor_key_ciphertexts.to_vec(),
    };
    let space = ViewingKeyAccount::account_size(recovery_count, auditor_count);

    CreatePdaAccount {
        fee_payer: enrollment_authority,
        new_account: &mut *viewing_key_account,
        space,
        owner: &crate::ID,
        signer_seeds: [VIEWING_KEY_ACCOUNT_PDA_SEED, owner_identity.as_ref()],
        bump,
    }
    .execute()
    .map_err(|_| SquadsZoneError::InvalidViewingKeyAccount)?;

    write_viewing_key_account(viewing_key_account, &account)
}

/// Overwrite the viewing key account data in place. The create path allocates
/// the account to exactly the serialized length, so `get_mut(..len)` covers
/// the full serialized form.
#[inline(never)]
fn write_viewing_key_account(
    account: &mut AccountView,
    value: &ViewingKeyAccount,
) -> ProgramResult {
    let bytes = value
        .serialize()
        .map_err(|_| SquadsZoneError::Deserialization)?;
    let mut data = account
        .try_borrow_mut()
        .map_err(|_| SquadsZoneError::InvalidViewingKeyAccount)?;
    let slot = data
        .get_mut(..bytes.len())
        .ok_or(SquadsZoneError::InvalidAccountSize)?;
    slot.copy_from_slice(&bytes);
    Ok(())
}
