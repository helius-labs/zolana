//! `cancel_key_update` (tag 15): cancel a queued key-update proposal before
//! execution and reclaim its rent to the recorded rent payer.

use pinocchio::{AccountView, ProgramResult};
use zolana_squads_interface::error::SquadsRingError;

use super::loader::load_key_update_proposal;
use crate::instructions::ring_config::loader::load_ring_config;
use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::shared::{close::close_account, owner::is_owner_identity};

/// Accounts: `[authority (signer), target_vka_account (readonly),
/// key_update_proposal (writable), rent_recipient (writable), ring_config
/// (readonly)]`.
///
/// The authority is the target's own owner or the ring co-signer. A keypair
/// owner is stored as a hash of its address and can never satisfy the owner
/// test, so without the co-signer such an account would have no close path and
/// a squatted proposal would block its domain forever.
#[inline(never)]
pub fn process_cancel_key_update_ix(accounts: &mut [AccountView], _data: &[u8]) -> ProgramResult {
    if accounts.len() < 5 {
        return Err(SquadsRingError::InvalidInstructionData.into());
    }
    let (authority, rest) = accounts
        .split_first_mut()
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let (target_vka_account, rest) = rest
        .split_first_mut()
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let (key_update_proposal, rest) = rest
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

    let target_vka = load_viewing_key_account(target_vka_account)?;
    let proposal = load_key_update_proposal(key_update_proposal)?;
    let ring = load_ring_config(ring_config)?;

    if proposal.target != *target_vka_account.address() {
        return Err(SquadsRingError::ProposalTargetMismatch.into());
    }
    if authority.address() != &ring.co_signer
        && !is_owner_identity(authority, target_vka.owner.to_bytes())?
    {
        return Err(SquadsRingError::OwnerMismatch.into());
    }
    if rent_recipient.address() != &proposal.rent_payer {
        return Err(SquadsRingError::RentRecipientMismatch.into());
    }

    close_account(
        key_update_proposal,
        rent_recipient,
        SquadsRingError::InvalidKeyUpdateProposal,
    )
}
