use pinocchio::{
    account::{Ref, RefMut},
    error::ProgramError,
    AccountView,
};
use zolana_interface::{error::ShieldedPoolError, state::ZoneConfig};

use crate::instructions::shared::{load_config, load_config_mut};

/// Load a zone config read-only: owned by SPP, correct size and discriminator.
/// The create-time `zone_auth` derivation already bound the account to its
/// program, so callers add only an `is_signer` check -- never re-deriving.
#[inline(always)]
pub fn load_zone_config(account: &AccountView) -> Result<Ref<'_, ZoneConfig>, ProgramError> {
    load_config(
        account,
        ShieldedPoolError::InvalidZoneConfig,
        ZoneConfig::has_discriminator,
    )
}

#[inline(always)]
pub fn load_zone_config_mut<'a>(
    account: &'a mut AccountView,
) -> Result<RefMut<'a, ZoneConfig>, ProgramError> {
    load_config_mut(
        account,
        ShieldedPoolError::InvalidZoneConfig,
        ZoneConfig::has_discriminator,
    )
}

/// Load the zone config mutably and require `authority` to be a signer that
/// matches the stored zone authority.
#[inline(always)]
pub fn load_and_validate_zone_authority_mut<'a>(
    config_account: &'a mut AccountView,
    authority_account: &AccountView,
) -> Result<RefMut<'a, ZoneConfig>, ProgramError> {
    if !authority_account.is_signer() {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    let config = load_zone_config_mut(config_account)?;
    if !config.check_authority(authority_account.address()) {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }
    Ok(config)
}
