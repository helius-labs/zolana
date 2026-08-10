//! Loader for the async proposal account. `Proposal` is a variable-length
//! wincode type, so the loader returns an owned value instead of a `Ref<T>`.

use pinocchio::{error::ProgramError, AccountView};
use zolana_squads_interface::{error::SquadsRingError, state::proposal::Proposal};

#[inline(always)]
pub fn load_proposal(account: &AccountView) -> Result<Proposal, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(SquadsRingError::InvalidAccountOwner.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| SquadsRingError::InvalidProposal)?;
    let value = Proposal::deserialize(&data).map_err(|_| SquadsRingError::Deserialization)?;
    if value.discriminator != Proposal::DISCRIMINATOR {
        return Err(SquadsRingError::InvalidDiscriminator.into());
    }
    Ok(value)
}
