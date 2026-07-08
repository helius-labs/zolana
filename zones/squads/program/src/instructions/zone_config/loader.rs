//! Loader for the singleton zone config account.
//!
//! Checks program ownership, borrows the account data, deserializes the owned
//! wincode struct, and rejects a mismatched discriminator. `ZoneConfig` is a
//! variable-length wincode type (not a zero-copy `bytemuck` cast), so the loader
//! returns an owned value rather than a `Ref<T>`.
//!
//! Mirrors the SPP loader pattern (owner check, deserialize, discriminator
//! check), adapted for owned wincode deserialization: a deserialize failure maps
//! to [`SquadsZoneError::Deserialization`], a discriminator mismatch to
//! [`SquadsZoneError::InvalidDiscriminator`], and a foreign owner to
//! [`SquadsZoneError::InvalidAccountOwner`].

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
