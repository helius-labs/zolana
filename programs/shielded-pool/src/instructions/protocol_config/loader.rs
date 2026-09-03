use pinocchio::{
    account::{Ref, RefMut},
    error::ProgramError,
    AccountView,
};
use zolana_interface::{error::ShieldedPoolError, state::ProtocolConfig};

use crate::instructions::shared::{load_config, load_config_mut};

// ---------------------------------------------------------------------------
// Protocol config
// ---------------------------------------------------------------------------

#[inline(always)]
pub fn load_protocol_config<'a>(
    account: &'a AccountView,
) -> Result<Ref<'a, ProtocolConfig>, ProgramError> {
    load_config(
        account,
        ShieldedPoolError::InvalidProtocolConfig,
        |config: &ProtocolConfig| config.check_discriminator().is_ok(),
    )
}

#[inline(always)]
pub fn load_protocol_config_mut<'a>(
    account: &'a mut AccountView,
) -> Result<RefMut<'a, ProtocolConfig>, ProgramError> {
    load_config_mut(
        account,
        ShieldedPoolError::InvalidProtocolConfig,
        |config: &ProtocolConfig| config.check_discriminator().is_ok(),
    )
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

#[inline(always)]
pub fn load_and_validate_fee_authority<'a>(
    config_account: &'a AccountView,
    authority_account: &AccountView,
) -> Result<Ref<'a, ProtocolConfig>, ProgramError> {
    if !authority_account.is_signer() {
        return Err(ShieldedPoolError::InvalidProtocolConfig.into());
    }
    let config = load_protocol_config(config_account)?;
    config
        .check_fee_authority(authority_account.address())
        .map_err(ShieldedPoolError::from)?;
    Ok(config)
}

/// Require `authority_account` to be the stored forester authority. The signer
/// check stays in the processor (`next_signer`) so both forester instructions
/// report `AccountError::InvalidSigner` for an unsigned authority.
#[inline(always)]
pub fn validate_forester_authority(
    config_account: &AccountView,
    authority_account: &AccountView,
) -> Result<(), ProgramError> {
    let config = load_protocol_config(config_account)?;
    config
        .check_forester_authority(authority_account.address())
        .map_err(ShieldedPoolError::from)?;
    Ok(())
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
