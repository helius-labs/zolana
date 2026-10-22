//! Loader for the async proposal account.
//!
//! Checks program ownership, borrows the account data, deserializes the owned
//! wincode struct, and rejects a mismatched discriminator. `Proposal` is a
//! variable-length wincode type (not a zero-copy `bytemuck` cast), so the loader
//! returns an owned value rather than a `Ref<T>`.
//!
//! Mirrors the SPP loader pattern (owner check, deserialize, discriminator
//! check), adapted for owned wincode deserialization: a deserialize failure maps
//! to [`SquadsRingError::Deserialization`], a discriminator mismatch to
//! [`SquadsRingError::InvalidDiscriminator`], and a foreign owner to
//! [`SquadsRingError::InvalidAccountOwner`].

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
