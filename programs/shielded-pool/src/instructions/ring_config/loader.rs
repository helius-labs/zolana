use pinocchio::{
    account::{Ref, RefMut},
    error::ProgramError,
    AccountView,
};
use zolana_interface::{error::ShieldedPoolError, state::RingConfig};

use crate::instructions::shared::{load_config, load_config_mut};

/// Load a ring config read-only: owned by SPP, correct size and discriminator.
/// The create-time `ring_auth` derivation already bound the account to its
/// program. Administrative callers use this loader directly; operational ring
/// callers add a signer check and use [`load_active_ring_config`].
#[inline(always)]
pub fn load_ring_config(account: &AccountView) -> Result<Ref<'_, RingConfig>, ProgramError> {
    load_config(
        account,
        ShieldedPoolError::InvalidRingConfig,
        RingConfig::has_discriminator,
    )
}

/// Load a signed ring config for an operational ring instruction and reject it
/// when governance has not activated the ring or the ring owner has paused it.
/// Callers must perform the signer check before invoking this loader.
///
/// This is the single gate for all four operational rails (`ring_deposit`,
/// `ring_transact`, `ring_authority_transact`, `ring_merge_transact`).
/// Activation is checked first so an inert config reports the governance reason
/// rather than being masked by a stale pause.
#[inline(always)]
pub fn load_active_ring_config(account: &AccountView) -> Result<Ref<'_, RingConfig>, ProgramError> {
    let config = load_ring_config(account)?;
    if !config.is_activated() {
        return Err(ShieldedPoolError::RingNotActivated.into());
    }
    if config.is_paused() {
        return Err(ShieldedPoolError::RingPaused.into());
    }
    Ok(config)
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
