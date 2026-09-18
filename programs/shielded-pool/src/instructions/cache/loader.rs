use crate::instructions::shared::{load_config, load_config_mut};
use pinocchio::{
    account::{Ref, RefMut},
    error::ProgramError,
    AccountView,
};
use zolana_interface::{error::ShieldedPoolError, state::cache::CacheAccount};

pub(crate) fn load_cache(account: &AccountView) -> Result<Ref<'_, CacheAccount>, ProgramError> {
    load_config(
        account,
        ShieldedPoolError::InvalidCache,
        CacheAccount::has_discriminator,
    )
}

pub(crate) fn load_cache_mut(
    account: &mut AccountView,
) -> Result<RefMut<'_, CacheAccount>, ProgramError> {
    load_config_mut(
        account,
        ShieldedPoolError::InvalidCache,
        CacheAccount::has_discriminator,
    )
}
