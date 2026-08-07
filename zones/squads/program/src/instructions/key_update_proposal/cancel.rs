//! `cancel_key_update` (tag 15): cancel a queued key-update proposal before
//! execution and reclaim its rent to the recorded rent payer.

use pinocchio::{AccountView, ProgramResult};
use zolana_squads_interface::error::SquadsZoneError;

use super::loader::load_key_update_proposal;
use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::instructions::zone_config::loader::load_zone_config;
use crate::shared::{close::close_account, owner::is_owner_identity};

/// Accounts: `[authority (signer), target_vka_account (readonly),
/// key_update_proposal (writable), rent_recipient (writable), zone_config
/// (readonly)]`.
///
/// The authority is the target's own owner or the zone co-signer. A keypair
/// owner is stored as a hash of its address and can never satisfy the owner
/// test, so without the co-signer such an account would have no close path and
/// a squatted proposal would block its domain forever.
#[inline(never)]
pub fn process_cancel_key_update_ix(accounts: &mut [AccountView], _data: &[u8]) -> ProgramResult {
    if accounts.len() < 5 {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    }
    let (authority, rest) = accounts
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (target_vka_account, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (key_update_proposal, rest) = rest
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

    let target_vka = load_viewing_key_account(target_vka_account)?;
    let proposal = load_key_update_proposal(key_update_proposal)?;
    let zone = load_zone_config(zone_config)?;

    if proposal.target != *target_vka_account.address() {
        return Err(SquadsZoneError::ProposalTargetMismatch.into());
    }
    if authority.address() != &zone.co_signer
        && !is_owner_identity(authority, target_vka.owner.to_bytes())?
    {
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
