use crate::instructions::shared::{load_config, load_config_mut};
use pinocchio::{
    account::{Ref, RefMut},
    address::address_eq,
    error::ProgramError,
    AccountView, ProgramResult,
};
use zolana_interface::{error::ShieldedPoolError, state::cache::CacheAccount};

pub(crate) fn load_cache(account: &AccountView) -> Result<Ref<'_, CacheAccount>, ProgramError> {
    load_config(
        account,
        ShieldedPoolError::InvalidCache,
        CacheAccount::is_valid,
    )
}

pub(crate) fn load_cache_mut(
    account: &mut AccountView,
) -> Result<RefMut<'_, CacheAccount>, ProgramError> {
    load_config_mut(
        account,
        ShieldedPoolError::InvalidCache,
        CacheAccount::is_valid,
    )
}

/// Check the optional final cache cannot also fill another instruction role.
pub(crate) fn check_cache_alias(accounts: &[AccountView], cache_present: bool) -> ProgramResult {
    if cache_present {
        let cache = accounts.last().ok_or(ShieldedPoolError::InvalidCache)?;
        if accounts
            .iter()
            .filter(|account| address_eq(account.address(), cache.address()))
            .take(2)
            .count()
            > 1
        {
            return Err(ShieldedPoolError::CacheAccountAlias.into());
        }
    }
    Ok(())
}
