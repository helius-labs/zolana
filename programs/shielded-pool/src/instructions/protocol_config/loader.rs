use bytemuck::{from_bytes, from_bytes_mut};
use pinocchio::{
    account::{Ref, RefMut},
    error::ProgramError,
    AccountView,
};
use zolana_interface::state::ProtocolConfig;

use zolana_interface::error::ShieldedPoolError;

// ---------------------------------------------------------------------------
// Protocol config
// ---------------------------------------------------------------------------

#[inline(always)]
pub fn load_protocol_config<'a>(
    account: &'a AccountView,
) -> Result<Ref<'a, ProtocolConfig>, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| ShieldedPoolError::InvalidProtocolConfig)?;
    if data.len() != ProtocolConfig::SIZE {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    let config = Ref::map(data, |d| from_bytes::<ProtocolConfig>(d));
    config
        .check_discriminator()
        .map_err(ShieldedPoolError::from)?;
    Ok(config)
}

#[inline(always)]
pub fn load_protocol_config_mut<'a>(
    account: &'a mut AccountView,
) -> Result<RefMut<'a, ProtocolConfig>, ProgramError> {
    if !account.is_writable() || !account.owned_by(&crate::ID) {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    let data = account
        .try_borrow_mut()
        .map_err(|_| ShieldedPoolError::InvalidProtocolConfig)?;
    if data.len() != ProtocolConfig::SIZE {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    let config = RefMut::map(data, |d| from_bytes_mut::<ProtocolConfig>(d));
    config
        .check_discriminator()
        .map_err(ShieldedPoolError::from)?;
    Ok(config)
}

/// Load the protocol config and require `authority` to be a signer that matches
/// the stored admin authority.
#[inline(always)]
pub fn load_and_validate_protocol_authority<'a>(
    config_account: &'a AccountView,
    authority_account: &AccountView,
) -> Result<Ref<'a, ProtocolConfig>, ProgramError> {
    if !authority_account.is_signer() {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    let config = load_protocol_config(config_account)?;
    config
        .check_protocol_authority(authority_account.address())
        .map_err(ShieldedPoolError::from)?;
    Ok(config)
}

/// Mutable counterpart of [`load_and_validate_protocol_authority`].
#[inline(always)]
pub fn load_and_validate_protocol_authority_mut<'a>(
    config_account: &'a mut AccountView,
    authority_account: &AccountView,
) -> Result<RefMut<'a, ProtocolConfig>, ProgramError> {
    if !authority_account.is_signer() {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    let config = load_protocol_config_mut(config_account)?;
    config
        .check_protocol_authority(authority_account.address())
        .map_err(ShieldedPoolError::from)?;
    Ok(config)
}
