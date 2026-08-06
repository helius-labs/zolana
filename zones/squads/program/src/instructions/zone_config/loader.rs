//! Loader for the singleton zone config account. `ZoneConfig` is a
//! variable-length wincode type, so the loader returns an owned value instead
//! of a `Ref<T>`.

use pinocchio::{error::ProgramError, AccountView};
use zolana_squads_interface::{error::SquadsZoneError, state::zone_config::ZoneConfig};

#[inline(always)]
pub fn load_zone_config(account: &AccountView) -> Result<ZoneConfig, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(SquadsZoneError::InvalidAccountOwner.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| SquadsZoneError::InvalidZoneConfig)?;
    let value = ZoneConfig::deserialize(&data).map_err(|_| SquadsZoneError::Deserialization)?;
    if value.discriminator != ZoneConfig::DISCRIMINATOR {
        return Err(SquadsZoneError::InvalidDiscriminator.into());
    }
    Ok(value)
}
