//! `cancel_proposal` (tag 12): cancel a queued proposal and refund rent.

use pinocchio::{AccountView, ProgramResult};
use zolana_squads_interface::error::SquadsRingError;

use super::loader::load_proposal;
use crate::instructions::ring_config::loader::load_ring_config;
use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::shared::{close::close_account, owner::is_owner_identity};

/// Accounts: `[authority (signer), viewing_key_account (readonly), proposal
/// (writable), rent_recipient (writable), ring_config (readonly)]`.
///
/// The authority is the account's own owner or the ring co-signer. A keypair
/// owner is stored as a hash of its address and can never satisfy the owner
/// test, so without the co-signer such a proposal could never be cancelled.
#[inline(never)]
pub fn process_cancel_proposal_ix(accounts: &mut [AccountView], _data: &[u8]) -> ProgramResult {
    if accounts.len() < 5 {
        return Err(SquadsRingError::InvalidInstructionData.into());
    }
    let (authority, rest) = accounts
        .split_first_mut()
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let (viewing_key_account, rest) = rest
        .split_first_mut()
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let (proposal, rest) = rest
        .split_first_mut()
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let (rent_recipient, rest) = rest
        .split_first_mut()
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let ring_config = rest
        .first()
        .ok_or(SquadsRingError::InvalidInstructionData)?;

    if !authority.is_signer() {
        return Err(SquadsRingError::MissingOwnerSignature.into());
    }

    let vka = load_viewing_key_account(viewing_key_account)?;
    let record = load_proposal(proposal)?;
    let ring = load_ring_config(ring_config)?;

    if authority.address() != &ring.co_signer
        && !is_owner_identity(authority, vka.owner.to_bytes())?
    {
        return Err(SquadsRingError::OwnerMismatch.into());
    }
    if record.owner != vka.owner {
        return Err(SquadsRingError::ProposalOwnershipMismatch.into());
    }
    if rent_recipient.address() != &record.rent_payer {
        return Err(SquadsRingError::RentRecipientMismatch.into());
    }

    close_account(proposal, rent_recipient, SquadsRingError::InvalidProposal)
}
