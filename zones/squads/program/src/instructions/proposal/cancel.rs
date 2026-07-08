//! `cancel_proposal` (tag 12): cancel a queued proposal and refund rent.

use pinocchio::{AccountView, ProgramResult};
use zolana_squads_interface::error::SquadsZoneError;

use super::loader::load_proposal;
use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::shared::close::close_account;
use crate::shared::proof::hash_field;

/// `cancel_proposal` (tag 12): cancel a queued proposal and refund rent.
///
/// Accounts: `[owner (signer), viewing_key_account (readonly), proposal
/// (writable), rent_recipient (writable)]`. Takes no instruction data.
#[inline(never)]
pub fn process_cancel_proposal_ix(accounts: &mut [AccountView], _data: &[u8]) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    }
    let (owner, rest) = accounts
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (viewing_key_account, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (proposal, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let rent_recipient = rest
        .first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;

    if !owner.is_signer() {
        return Err(SquadsZoneError::MissingOwnerSignature.into());
    }

    let vka = load_viewing_key_account(viewing_key_account)?;
    let record = load_proposal(proposal)?;

    // The owner identity is the pk-field-hash of the signer (matches `create`).
    let owner_field = hash_field(
        &owner.address().to_bytes(),
        SquadsZoneError::ProofHashingFailed,
    )?;
    if owner_field != vka.owner.to_bytes() {
        return Err(SquadsZoneError::OwnerMismatch.into());
    }
    if record.owner != vka.owner {
        return Err(SquadsZoneError::ProposalOwnershipMismatch.into());
    }
    if rent_recipient.address() != &record.rent_payer {
        return Err(SquadsZoneError::RentRecipientMismatch.into());
    }

    close_account(proposal, rent_recipient, SquadsZoneError::InvalidProposal)
}
