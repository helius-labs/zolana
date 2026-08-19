use pinocchio::{address::address_eq, AccountView, Address, ProgramResult};
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::loader::load_config_mut,
    state::{
        ASSETS_ALLOWLIST, ASSETS_ANY, MAX_ASSETS, WITHDRAWALS_APPROVAL, WITHDRAWALS_BLOCKED,
        WITHDRAWALS_OPEN,
    },
};

/// One asset table entry: a mint and its withdrawal rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct AssetRule {
    pub mint: [u8; 32],
    pub withdrawals: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SetPolicyIxData {
    /// Withdrawal rule for assets without a table entry.
    pub withdrawals: u8,
    /// `ASSETS_ANY` or `ASSETS_ALLOWLIST`.
    pub asset_policy: u8,
    /// All zero when no rule is `WITHDRAWALS_APPROVAL`.
    pub approver: [u8; 32],
    /// At most `MAX_ASSETS` entries.
    #[wincode(with = "containers::Vec<AssetRule, FixIntLen<u8>>")]
    pub assets: Vec<AssetRule>,
}

fn is_rule(value: u8) -> bool {
    matches!(
        value,
        WITHDRAWALS_OPEN | WITHDRAWALS_BLOCKED | WITHDRAWALS_APPROVAL
    )
}

/// Replaces the ring's policy. Accounts `[authority(s), config(w)]`; the
/// authority is the one `create_config` recorded.
#[inline(never)]
pub fn process_set_policy_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let SetPolicyIxData {
        withdrawals,
        asset_policy,
        approver,
        assets,
    } = wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;
    let needs_approver = withdrawals == WITHDRAWALS_APPROVAL
        || assets
            .iter()
            .any(|asset| asset.withdrawals == WITHDRAWALS_APPROVAL);
    if !is_rule(withdrawals)
        || !matches!(asset_policy, ASSETS_ANY | ASSETS_ALLOWLIST)
        || assets.len() > MAX_ASSETS
        || assets.iter().any(|asset| !is_rule(asset.withdrawals))
        || (needs_approver && approver == [0u8; 32])
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
    config.approver = Address::new_from_array(approver);
    config.assets = [[0u8; 32]; MAX_ASSETS];
    config.asset_withdrawals = [0u8; MAX_ASSETS];
    for (index, asset) in assets.iter().enumerate() {
        config.assets[index] = asset.mint;
        config.asset_withdrawals[index] = asset.withdrawals;
    }
    config.assets_len = assets.len() as u8;
    Ok(())
}
