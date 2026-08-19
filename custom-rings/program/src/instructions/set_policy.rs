use pinocchio::{address::address_eq, AccountView, ProgramResult};
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::loader::load_config_mut,
    state::{
        ASSETS_ALLOWLIST, ASSETS_ANY, MAX_ALLOWED_ASSETS, WITHDRAWALS_BLOCKED, WITHDRAWALS_OPEN,
    },
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SetPolicyIxData {
    /// `WITHDRAWALS_OPEN` or `WITHDRAWALS_BLOCKED`.
    pub withdrawals: u8,
    /// `ASSETS_ANY` or `ASSETS_ALLOWLIST`.
    pub asset_policy: u8,
    /// Mints accepted under the allowlist, at most `MAX_ALLOWED_ASSETS`.
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub allowed_assets: Vec<[u8; 32]>,
}

/// Replaces the ring's policy. Accounts `[authority(s), config(w)]`; the
/// authority is the one `create_config` recorded.
#[inline(never)]
pub fn process_set_policy_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let SetPolicyIxData {
        withdrawals,
        asset_policy,
        allowed_assets,
    } = wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;
    if !matches!(withdrawals, WITHDRAWALS_OPEN | WITHDRAWALS_BLOCKED)
        || !matches!(asset_policy, ASSETS_ANY | ASSETS_ALLOWLIST)
        || allowed_assets.len() > MAX_ALLOWED_ASSETS
    {
        return Err(CustomRingError::InvalidPolicy.into());
    }

    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config_account = iter.next_mut("config")?;

    let mut config = load_config_mut(config_account)?;
    if !address_eq(&config.authority, authority.address()) {
        return Err(CustomRingError::UnauthorizedAuthority.into());
    }
    config.withdrawals = withdrawals;
    config.asset_policy = asset_policy;
    config.allowed_assets = [[0u8; 32]; MAX_ALLOWED_ASSETS];
    for (slot, mint) in config.allowed_assets.iter_mut().zip(&allowed_assets) {
        *slot = *mint;
    }
    config.allowed_assets_len = allowed_assets.len() as u8;
    Ok(())
}
