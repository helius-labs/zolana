//! `cancel_key_update` (tag 15): cancel a queued key-update proposal before
//! execution and reclaim its rent to the recorded rent payer.

use pinocchio::{AccountView, ProgramResult};
use zolana_squads_interface::error::SquadsZoneError;

use super::loader::load_key_update_proposal;
use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::shared::close::close_account;

/// `cancel_key_update` (tag 15): cancel a queued key-update proposal before
/// execution and reclaim its rent to the recorded rent payer.
///
/// Accounts: `[owner (signer), target_vka_account (readonly), key_update_proposal
/// (writable), rent_recipient (writable)]`.
#[inline(never)]
pub fn process_cancel_key_update_ix(accounts: &mut [AccountView], _data: &[u8]) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    }
    let (owner, rest) = accounts
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (target_vka_account, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (key_update_proposal, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let rent_recipient = rest
        .first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;

    if !owner.is_signer() {
        return Err(SquadsZoneError::MissingOwnerSignature.into());
    }

    let target_vka = load_viewing_key_account(target_vka_account)?;
    let proposal = load_key_update_proposal(key_update_proposal)?;

    if proposal.target != *target_vka_account.address() {
        return Err(SquadsZoneError::ProposalTargetMismatch.into());
    }
    if owner.address() != &target_vka.owner {
        return Err(SquadsZoneError::OwnerMismatch.into());
    }
    if rent_recipient.address() != &proposal.rent_payer {
        return Err(SquadsZoneError::RentRecipientMismatch.into());
    }

    close_account(
        key_update_proposal,
        rent_recipient,
        SquadsZoneError::InvalidKeyUpdateProposal,
    )
}
