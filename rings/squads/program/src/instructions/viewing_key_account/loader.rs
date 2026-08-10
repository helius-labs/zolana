//! Loader for the per-owner viewing key account. `ViewingKeyAccount` is a
//! variable-length wincode type, so the loader returns an owned value instead
//! of a `Ref<T>`.

use pinocchio::{error::ProgramError, AccountView};
use zolana_squads_interface::{
    error::SquadsRingError, state::viewing_key_account::ViewingKeyAccount,
};

#[inline(always)]
pub fn load_viewing_key_account(account: &AccountView) -> Result<ViewingKeyAccount, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(SquadsRingError::InvalidAccountOwner.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| SquadsRingError::InvalidViewingKeyAccount)?;
    let value =
        ViewingKeyAccount::deserialize(&data).map_err(|_| SquadsRingError::Deserialization)?;
    if value.discriminator != ViewingKeyAccount::DISCRIMINATOR {
        return Err(SquadsRingError::InvalidDiscriminator.into());
    }
    // Parse the owner kind here so no later branch can treat an unknown byte as
    // the signatureless rail.
    value.kind()?;
    Ok(value)
}
