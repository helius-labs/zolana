//! Loader for the async proposal account. `Proposal` is a variable-length
//! wincode type, so the loader returns an owned value instead of a `Ref<T>`.

use pinocchio::{error::ProgramError, AccountView};
use zolana_squads_interface::{error::SquadsZoneError, state::proposal::Proposal};

#[inline(always)]
pub fn load_proposal(account: &AccountView) -> Result<Proposal, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(SquadsZoneError::InvalidAccountOwner.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| SquadsZoneError::InvalidProposal)?;
    let value = Proposal::deserialize(&data).map_err(|_| SquadsZoneError::Deserialization)?;
    if value.discriminator != Proposal::DISCRIMINATOR {
        return Err(SquadsZoneError::InvalidDiscriminator.into());
    }
    Ok(value)
}
