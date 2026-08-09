//! `cancel_proposal` (tag 12): cancel a queued proposal and refund rent.

use pinocchio::{AccountView, ProgramResult};
use zolana_squads_interface::error::SquadsZoneError;

use super::loader::load_proposal;
use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::instructions::zone_config::loader::load_zone_config;
use crate::shared::{close::close_account, owner::is_owner_identity};

/// Accounts: `[authority (signer), viewing_key_account (readonly), proposal
/// (writable), rent_recipient (writable), zone_config (readonly)]`.
///
/// The authority is the account's own owner or the zone co-signer. A keypair
/// owner is stored as a hash of its address and can never satisfy the owner
/// test, so without the co-signer such a proposal could never be cancelled.
#[inline(never)]
pub fn process_cancel_proposal_ix(accounts: &mut [AccountView], _data: &[u8]) -> ProgramResult {
    if accounts.len() < 5 {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    }
    let (authority, rest) = accounts
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (viewing_key_account, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (proposal, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (rent_recipient, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let zone_config = rest
        .first()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;

    if !authority.is_signer() {
        return Err(SquadsZoneError::MissingOwnerSignature.into());
    }

    let vka = load_viewing_key_account(viewing_key_account)?;
    let record = load_proposal(proposal)?;
    let zone = load_zone_config(zone_config)?;

    if authority.address() != &zone.co_signer
        && !is_owner_identity(authority, vka.owner.to_bytes())?
    {
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
