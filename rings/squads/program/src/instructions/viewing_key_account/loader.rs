//! Loader for the per-owner viewing key account. `ViewingKeyAccount` is a
//! variable-length wincode type, so the loader returns an owned value instead
//! of a `Ref<T>`.

use pinocchio::{error::ProgramError, AccountView};
use zolana_squads_interface::{
    error::SquadsZoneError, state::viewing_key_account::ViewingKeyAccount,
};

#[inline(always)]
pub fn load_viewing_key_account(account: &AccountView) -> Result<ViewingKeyAccount, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(SquadsZoneError::InvalidAccountOwner.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| SquadsZoneError::InvalidViewingKeyAccount)?;
    let value =
        ViewingKeyAccount::deserialize(&data).map_err(|_| SquadsZoneError::Deserialization)?;
    if value.discriminator != ViewingKeyAccount::DISCRIMINATOR {
        return Err(SquadsZoneError::InvalidDiscriminator.into());
    }
    // Parse the owner kind here so no later branch can treat an unknown byte as
    // the signatureless rail.
    value.kind()?;
    Ok(value)
}
