//! `create_viewing_key_account` (tag 5): verify the KEY-ENCRYPTION proof and
//! initialize the per-owner viewing key account PDA.

use pinocchio::{AccountView, ProgramResult};
use zolana_squads_interface::{
    constants::{
        ENCRYPTION_SCHEME_P256_AES, OWNER_KIND_KEYPAIR, OWNER_KIND_SMART_ACCOUNT,
        REQUIRED_AUDITOR_KEY_COUNT, VIEWING_KEY_STATE_ACTIVE,
    },
    error::SquadsZoneError,
    instruction::instruction_data::CreateViewingKeyAccountIxData,
    state::viewing_key_account::ViewingKeyAccount,
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
/// Accounts: `[fee_payer (signer, writable), owner, viewing_key_account
/// (writable, the PDA), zone_config (readonly), system_program]`.
///
/// The instruction carries a combined `key_ciphertexts` vector ordered recovery
/// ciphertexts first, then auditor; the recipient public keys are the
/// instruction's `recovery_keys` followed by the auditor keys read from
/// `zone_config`. The proof is recomputed over `old_state_hash = 0` (creation).
#[inline(never)]
pub fn process_create_viewing_key_account_ix(
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 5 {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    }
    let (fee_payer, rest) = accounts
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (owner, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (viewing_key_account, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let zone_config = rest
        .first()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;

    if !fee_payer.is_signer() {
        return Err(SquadsZoneError::MissingAuthoritySignature.into());
    }

    let ix = CreateViewingKeyAccountIxData::deserialize(data)
        .map_err(|_| SquadsZoneError::InvalidInstructionData)?;

    if ix.encryption_scheme != ENCRYPTION_SCHEME_P256_AES {
        return Err(SquadsZoneError::InvalidEncryptionScheme.into());
    }

    // The owner kind is client-selected but must be a known variant: a keypair
    // (P256 rail) or a smart-account (signatureless vault rail) owner.
    if ix.owner_kind != OWNER_KIND_KEYPAIR && ix.owner_kind != OWNER_KIND_SMART_ACCOUNT {
        return Err(SquadsZoneError::InvalidOwnerKind.into());
    }

    // Owner-signer rule (spec): a recovery-key holder authorizes adding its own
    // keys, so a non-empty `recovery_keys` set requires the owner to sign. An
    // auditor-only account (no recovery keys) does not require the owner.
    if !ix.recovery_keys.is_empty() && !owner.is_signer() {
        return Err(SquadsZoneError::MissingOwnerSignature.into());
    }

    // Auditor keys come from the zone config, not instruction data.
    let zone_config = load_zone_config(zone_config)?;
    if zone_config.auditor_keys.len() != REQUIRED_AUDITOR_KEY_COUNT {
        return Err(SquadsZoneError::InvalidAuditorKeyCount.into());
    }
    let auditor_keys = zone_config.auditor_keys;

    // The combined ciphertext vector is recovery ciphertexts first, then auditor.
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

    // Build the proof's recipient keys: recovery keys then auditor keys, each
    // paired with its ciphertext in the same order. `circuit.go:101`.
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

    // Bind the owner address before mutating other accounts, so no borrow on
    // `owner` is held across the PDA creation / data write-back.
    let owner_addr = *owner.address();

    let bump = verify_pda(
        viewing_key_account.address(),
        &[VIEWING_KEY_ACCOUNT_PDA_SEED, owner_addr.as_ref()],
        &crate::ID,
    )?;

    let account = ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: owner_addr,
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
        fee_payer,
        new_account: &mut *viewing_key_account,
        space,
        owner: &crate::ID,
        signer_seeds: [VIEWING_KEY_ACCOUNT_PDA_SEED, owner_addr.as_ref()],
        bump,
    }
    .execute()
    .map_err(|_| SquadsZoneError::InvalidViewingKeyAccount)?;

    write_viewing_key_account(viewing_key_account, &account)
}

/// Serialize `account` and overwrite the viewing key account data in place. The
/// account is allocated to exactly the serialized length by the create path, so
/// `get_mut(..len)` always covers the full serialized form (mirrors
/// `zone_config::create::write_zone_config`).
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
