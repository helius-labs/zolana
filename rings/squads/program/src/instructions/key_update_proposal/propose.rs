//! `update_viewing_key_account` (tag 6): create a `KeyUpdateProposal` PDA that
//! buffers a recovery-key rotation (or a single auditor update).

use pinocchio::{
    cpi::{Seed, Signer},
    AccountView, ProgramResult, Resize,
};
use zolana_squads_interface::{
    constants::{
        KEY_OP_ADD, KEY_OP_REMOVE, KEY_OP_REPLACE, KEY_OP_UPDATE_AUDITOR,
        REQUIRED_AUDITOR_KEY_COUNT,
    },
    error::SquadsRingError,
    instruction::instruction_data::UpdateViewingKeyAccountIxData,
    state::key_update_proposal::{KeyOperation, KeyUpdateProposal, OpenKeyUpdateProposal},
    KEY_UPDATE_PROPOSAL_PDA_SEED,
};

use crate::instructions::ring_config::loader::load_ring_config;
use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::shared::{owner::is_owner_identity, pda::verify_pda};

/// A proposal carries either a batch of recovery-key ops or a single
/// auditor-update op, never both (spec).
#[inline(always)]
fn is_auditor_update(operations: &[KeyOperation]) -> Result<bool, SquadsRingError> {
    let mut any_auditor = false;
    let mut any_recovery = false;
    for operation in operations {
        match operation.op {
            KEY_OP_UPDATE_AUDITOR => any_auditor = true,
            KEY_OP_ADD | KEY_OP_REMOVE | KEY_OP_REPLACE => any_recovery = true,
            _ => return Err(SquadsRingError::InvalidKeyOperation),
        }
    }
    if any_auditor && (any_recovery || operations.len() != 1) {
        return Err(SquadsRingError::MixedKeyOperationTypes);
    }
    Ok(any_auditor)
}

/// Accounts: `[proposer (signer, writable, fee payer), target_vka_account (readonly),
/// key_update_proposal (writable, the PDA), system_program (readonly),
/// ring_config (readonly)]`.
///
/// The proposal account is funded for the full buffer (one ciphertext per
/// resulting recovery key plus one per auditor) now, because the later
/// `fill_key_update` instructions have no system program to top up rent. The
/// stored data is then truncated to the empty-buffer length, so the buffer can
/// grow into rent already paid.
#[inline(never)]
pub fn process_update_viewing_key_account_ix(
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 5 {
        return Err(SquadsRingError::InvalidInstructionData.into());
    }
    let (proposer, rest) = accounts
        .split_first_mut()
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let (target_vka_account, rest) = rest
        .split_first_mut()
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let (key_update_proposal, rest) = rest
        .split_first_mut()
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    // accounts[3] is the system program (read by the create CPI implicitly).
    let ring_config = rest.get(1).ok_or(SquadsRingError::InvalidInstructionData)?;

    if !proposer.is_signer() {
        return Err(SquadsRingError::MissingAuthoritySignature.into());
    }

    let ix = UpdateViewingKeyAccountIxData::deserialize(data)
        .map_err(|_| SquadsRingError::InvalidInstructionData)?;

    let target_vka = load_viewing_key_account(target_vka_account)?;
    let ring_config = load_ring_config(ring_config)?;

    // The proposal address is derived from caller-chosen seeds, so an unbound
    // creator could park a proposal on a victim's target and block every later
    // rotation at that domain. The co-signer is the recovery party for an owner
    // that cannot sign, so it stays authorized alongside the owner.
    let co_signer = proposer.address() == &ring_config.co_signer;
    if !co_signer && !is_owner_identity(proposer, target_vka.owner.to_bytes())? {
        return Err(SquadsRingError::OwnerMismatch.into());
    }

    let auditor_update = is_auditor_update(&ix.operations)?;

    let resulting_recovery = if auditor_update {
        if !co_signer {
            return Err(SquadsRingError::CoSignerMismatch.into());
        }
        if ring_config.auditor_keys == target_vka.auditor_keys {
            return Err(SquadsRingError::AuditorNotChanged.into());
        }
        // The recovery key count is unchanged by an auditor update.
        target_vka.recovery_keys.len()
    } else if ix.operations.is_empty() {
        // Rotating encrypted key material without changing the recipient set does
        // not add, remove, or replace an owner-controlled recovery key.
        target_vka.recovery_keys.len()
    } else {
        // A P-256 owner identity is not a Solana signer. Until a versioned
        // signed-intent scheme authenticates that owner, accepting a proposer
        // signature here would let any signer rewrite the recovery set.
        return Err(SquadsRingError::RecoveryKeyUpdateUnsupported.into());
    };

    let buffer_capacity = resulting_recovery
        .checked_add(REQUIRED_AUDITOR_KEY_COUNT)
        .ok_or(SquadsRingError::ArithmeticOverflow)?;

    // Bind the target address before mutating other accounts so no borrow on
    // `target_vka_account` is held across the PDA creation / data write-back.
    let target_addr = *target_vka_account.address();
    let domain_bytes = ix.domain.to_le_bytes();
    // The nonce is a seed so a completed rotation frees the domain again. A
    // proposal left behind keeps the address it was opened at, which no later
    // rotation of this account can collide with.
    let key_nonce = target_vka.key_nonce;
    let key_nonce_bytes = key_nonce.to_le_bytes();

    let bump = verify_pda(
        key_update_proposal.address(),
        &[
            KEY_UPDATE_PROPOSAL_PDA_SEED,
            target_addr.as_ref(),
            &domain_bytes,
            &key_nonce_bytes,
        ],
        &crate::ID,
    )?;

    let full_space = KeyUpdateProposal::account_size(ix.operations.len(), buffer_capacity);

    let bump_seed = [bump];
    let signer_seeds = [
        Seed::from(KEY_UPDATE_PROPOSAL_PDA_SEED),
        Seed::from(target_addr.as_ref()),
        Seed::from(domain_bytes.as_ref()),
        Seed::from(key_nonce_bytes.as_ref()),
        Seed::from(bump_seed.as_ref()),
    ];
    pinocchio_system::create_account_with_minimum_balance_signed(
        &mut *key_update_proposal,
        full_space,
        &crate::ID,
        proposer,
        None,
        &[Signer::from(signer_seeds.as_ref())],
    )
    .map_err(|_| SquadsRingError::InvalidKeyUpdateProposal)?;

    let proposal = KeyUpdateProposal::from(OpenKeyUpdateProposal {
        domain: ix.domain,
        target: target_addr,
        key_nonce,
        operations: ix.operations,
        expiry: ix.expiry,
        executor: ix.executor,
        rent_payer: *proposer.address(),
    });
    let bytes = proposal
        .serialize()
        .map_err(|_| SquadsRingError::Serialization)?;

    key_update_proposal
        .resize(bytes.len())
        .map_err(|_| SquadsRingError::InvalidAccountSize)?;
    {
        let mut account_data = key_update_proposal
            .try_borrow_mut()
            .map_err(|_| SquadsRingError::InvalidKeyUpdateProposal)?;
        let slot = account_data
            .get_mut(..bytes.len())
            .ok_or(SquadsRingError::InvalidAccountSize)?;
        slot.copy_from_slice(&bytes);
    }

    Ok(())
}
