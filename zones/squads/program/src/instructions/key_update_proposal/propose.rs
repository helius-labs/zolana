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
    error::SquadsZoneError,
    instruction::instruction_data::UpdateViewingKeyAccountIxData,
    state::key_update_proposal::{KeyOperation, KeyUpdateProposal},
    KEY_UPDATE_PROPOSAL_PDA_SEED,
};

use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::instructions::zone_config::loader::load_zone_config;
use crate::shared::pda::verify_pda;

/// A proposal carries either a batch of recovery-key ops or a single
/// auditor-update op; the two are never mixed (spec). Returns `true` when the
/// proposal is the single auditor-update variant.
#[inline(always)]
fn is_auditor_update(operations: &[KeyOperation]) -> Result<bool, SquadsZoneError> {
    let any_auditor = operations.iter().any(|op| op.op == KEY_OP_UPDATE_AUDITOR);
    if !any_auditor {
        return Ok(false);
    }
    // Auditor update must be the sole operation.
    if operations.len() != 1 {
        return Err(SquadsZoneError::MixedKeyOperationTypes);
    }
    Ok(true)
}

/// Simulate `operations` against a recovery list of `start_len` keys, validating
/// each op's index in bounds against the evolving list, and return the resulting
/// recovery-key count `R'`. The auditor-update variant leaves the count
/// unchanged. Used by `update_viewing_key_account` to size the buffer; the full
/// key application happens at `execute_key_update`.
#[inline(never)]
fn simulate_recovery_count(
    operations: &[KeyOperation],
    start_len: usize,
) -> Result<usize, SquadsZoneError> {
    let mut len = start_len;
    for op in operations {
        match op.op {
            KEY_OP_UPDATE_AUDITOR => {
                // Auditor update does not touch the recovery list.
            }
            KEY_OP_ADD => {
                len = len
                    .checked_add(1)
                    .ok_or(SquadsZoneError::ArithmeticOverflow)?;
            }
            KEY_OP_REMOVE => {
                if (op.index as usize) >= len {
                    return Err(SquadsZoneError::InvalidKeyOperationIndex);
                }
                len = len
                    .checked_sub(1)
                    .ok_or(SquadsZoneError::InvalidKeyOperationIndex)?;
            }
            KEY_OP_REPLACE => {
                if (op.index as usize) >= len {
                    return Err(SquadsZoneError::InvalidKeyOperationIndex);
                }
                // Count unchanged.
            }
            _ => return Err(SquadsZoneError::InvalidKeyOperation),
        }
    }
    Ok(len)
}

/// `update_viewing_key_account` (tag 6): create a `KeyUpdateProposal` PDA that
/// buffers a recovery-key rotation (or a single auditor update) for the executor
/// to fill and later settle via `execute_key_update`.
///
/// Accounts: `[proposer (signer, writable, fee payer), target_vka_account (readonly),
/// key_update_proposal (writable, the PDA), system_program (readonly),
/// zone_config (readonly)]`.
///
/// The proposal account is funded for the FULL size (`K = R' + A` ciphertexts)
/// now, because the later `fill_key_update` instructions have no system program
/// to top up rent for the growing buffer. The stored data is then truncated to
/// the empty-buffer length, leaving the account over-funded so the buffer can
/// grow into rent already paid.
#[inline(never)]
pub fn process_update_viewing_key_account_ix(
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 5 {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    }
    let (proposer, rest) = accounts
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (target_vka_account, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (key_update_proposal, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    // accounts[3] is the system program (read by the create CPI implicitly).
    let zone_config = rest.get(1).ok_or(SquadsZoneError::InvalidInstructionData)?;

    if !proposer.is_signer() {
        return Err(SquadsZoneError::MissingAuthoritySignature.into());
    }

    let ix = UpdateViewingKeyAccountIxData::deserialize(data)
        .map_err(|_| SquadsZoneError::InvalidInstructionData)?;

    let target_vka = load_viewing_key_account(target_vka_account)?;
    let zone_config = load_zone_config(zone_config)?;

    // EITHER a batch of recovery-key ops OR a single auditor update; never mixed.
    let auditor_update = is_auditor_update(&ix.operations)?;

    let resulting_recovery = if auditor_update {
        // Auditor-update path: the co-signer must propose it, and the zone's
        // auditor keys must actually differ from the target's stored auditor keys.
        if proposer.address() != &zone_config.co_signer {
            return Err(SquadsZoneError::CoSignerMismatch.into());
        }
        if zone_config.auditor_keys == target_vka.auditor_keys {
            return Err(SquadsZoneError::AuditorNotChanged.into());
        }
        // The recovery key count is unchanged by an auditor update.
        target_vka.recovery_keys.len()
    } else {
        // Recovery-ops path: validate indices and compute the resulting count.
        simulate_recovery_count(&ix.operations, target_vka.recovery_keys.len())?
    };

    // Buffer capacity: one ciphertext per resulting recovery key plus the
    // auditors.
    let buffer_capacity = resulting_recovery
        .checked_add(REQUIRED_AUDITOR_KEY_COUNT)
        .ok_or(SquadsZoneError::ArithmeticOverflow)?;

    // Bind the target address before mutating other accounts so no borrow on
    // `target_vka_account` is held across the PDA creation / data write-back.
    let target_addr = *target_vka_account.address();
    let domain_bytes = ix.domain.to_le_bytes();

    let bump = verify_pda(
        key_update_proposal.address(),
        &[
            KEY_UPDATE_PROPOSAL_PDA_SEED,
            target_addr.as_ref(),
            &domain_bytes,
        ],
        &crate::ID,
    )?;

    // Fund rent for the FULL buffer now (fill_key_update can't top up rent).
    let full_space = KeyUpdateProposal::account_size(ix.operations.len(), buffer_capacity);

    let bump_seed = [bump];
    let signer_seeds = [
        Seed::from(KEY_UPDATE_PROPOSAL_PDA_SEED),
        Seed::from(target_addr.as_ref()),
        Seed::from(domain_bytes.as_ref()),
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
    .map_err(|_| SquadsZoneError::InvalidKeyUpdateProposal)?;

    // Build the proposal with an EMPTY buffer; fill_key_update appends later. The
    // account stays funded for `full_space`, so the later grows are covered.
    let proposal = KeyUpdateProposal::new(
        ix.domain,
        target_addr,
        ix.operations,
        Vec::new(),
        ix.expiry,
        ix.executor,
        *proposer.address(),
    );
    let bytes = proposal
        .serialize()
        .map_err(|_| SquadsZoneError::Deserialization)?;

    // Truncate the data length down to the empty-buffer serialized length; the
    // over-funded rent (for `full_space`) stays with the account.
    key_update_proposal
        .resize(bytes.len())
        .map_err(|_| SquadsZoneError::InvalidAccountSize)?;
    {
        let mut account_data = key_update_proposal
            .try_borrow_mut()
            .map_err(|_| SquadsZoneError::InvalidKeyUpdateProposal)?;
        let slot = account_data
            .get_mut(..bytes.len())
            .ok_or(SquadsZoneError::InvalidAccountSize)?;
        slot.copy_from_slice(&bytes);
    }

    Ok(())
}
