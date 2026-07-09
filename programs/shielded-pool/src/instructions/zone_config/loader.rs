use bytemuck::{from_bytes, from_bytes_mut};
use pinocchio::{
    account::{Ref, RefMut},
    error::ProgramError,
    AccountView,
};
use rings_interface::{error::ShieldedPoolError, state::ZoneConfig};

/// Load a zone config read-only: owned by SPP, correct size and discriminator.
/// The create-time `zone_auth` derivation already bound the account to its
/// program, so callers add only an `is_signer` check -- never re-deriving.
#[inline(always)]
pub fn load_zone_config(account: &AccountView) -> Result<Ref<'_, ZoneConfig>, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| ShieldedPoolError::InvalidZoneConfig)?;
    if data.len() != ZoneConfig::SIZE {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    let config = Ref::map(data, |d| from_bytes::<ZoneConfig>(d));
    if !config.has_discriminator() {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    Ok(config)
}

#[inline(always)]
pub fn load_zone_config_mut<'a>(
    account: &'a mut AccountView,
) -> Result<RefMut<'a, ZoneConfig>, ProgramError> {
    if !account.is_writable() || !account.owned_by(&crate::ID) {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    let data = account
        .try_borrow_mut()
        .map_err(|_| ShieldedPoolError::InvalidZoneConfig)?;
    if data.len() != ZoneConfig::SIZE {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    let config = RefMut::map(data, |d| from_bytes_mut::<ZoneConfig>(d));
    if !config.has_discriminator() {
        return Err(ShieldedPoolError::InvalidZoneConfig.into());
    }
    Ok(config)
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
