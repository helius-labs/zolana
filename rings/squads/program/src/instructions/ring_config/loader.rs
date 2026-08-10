//! Loader for the singleton ring config account. `SquadsRingConfig` is a
//! variable-length wincode type, so the loader returns an owned value instead
//! of a `Ref<T>`.

use pinocchio::{error::ProgramError, AccountView};
use zolana_squads_interface::{error::SquadsRingError, state::ring_config::SquadsRingConfig};

#[inline(always)]
pub fn load_ring_config(account: &AccountView) -> Result<SquadsRingConfig, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(SquadsRingError::InvalidAccountOwner.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| SquadsRingError::InvalidRingConfig)?;
    let value =
        SquadsRingConfig::deserialize(&data).map_err(|_| SquadsRingError::Deserialization)?;
    if value.discriminator != SquadsRingConfig::DISCRIMINATOR {
        return Err(SquadsRingError::InvalidDiscriminator.into());
    }
    Ok(value)
}
