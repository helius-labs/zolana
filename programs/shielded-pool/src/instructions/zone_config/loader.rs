use pinocchio::{
    account::{Ref, RefMut},
    error::ProgramError,
    AccountView,
};
use zolana_interface::{error::ShieldedPoolError, state::RingConfig};

use crate::instructions::shared::{load_config, load_config_mut};

/// Load a ring config read-only: owned by SPP, correct size and discriminator.
/// The create-time `ring_auth` derivation already bound the account to its
/// program, so callers add only an `is_signer` check -- never re-deriving.
#[inline(always)]
pub fn load_ring_config(account: &AccountView) -> Result<Ref<'_, RingConfig>, ProgramError> {
    load_config(
        account,
        ShieldedPoolError::InvalidRingConfig,
        RingConfig::has_discriminator,
    )
}

#[inline(always)]
pub fn load_ring_config_mut<'a>(
    account: &'a mut AccountView,
) -> Result<RefMut<'a, RingConfig>, ProgramError> {
    load_config_mut(
        account,
        ShieldedPoolError::InvalidRingConfig,
        RingConfig::has_discriminator,
    )
}

/// Load the ring config mutably and require `authority` to be a signer that
/// matches the stored ring authority.
#[inline(always)]
pub fn load_and_validate_ring_authority_mut<'a>(
    config_account: &'a mut AccountView,
    authority_account: &AccountView,
) -> Result<RefMut<'a, RingConfig>, ProgramError> {
    if !authority_account.is_signer() {
        return Err(ShieldedPoolError::InvalidRingConfig.into());
    }
    let config = load_ring_config_mut(config_account)?;
    if !config.check_authority(authority_account.address()) {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }
    Ok(config)
}
