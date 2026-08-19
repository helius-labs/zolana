use pinocchio::{address::address_eq, AccountView, Address, ProgramResult};
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::loader::load_config_mut,
    state::{AssetPolicy, AssetRule, WithdrawalRule, MAX_ASSETS},
};

/// One asset table entry on the wire, `withdrawals` a `WithdrawalRule`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct AssetRuleData {
    pub mint: [u8; 32],
    pub withdrawals: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SetPolicyIxData {
    /// `WithdrawalRule` for assets without a table entry.
    pub withdrawals: u8,
    /// `AssetPolicy`.
    pub asset_policy: u8,
    /// All zero when no rule is `WithdrawalRule::Approval`.
    pub approver: [u8; 32],
    /// At most `MAX_ASSETS` entries, distinct mints.
    #[wincode(with = "containers::Vec<AssetRuleData, FixIntLen<u8>>")]
    pub assets: Vec<AssetRuleData>,
}

/// Replaces the ring's policy. Accounts `[authority(s), config(w)]`, the
/// authority being the one `create_config` recorded.
#[inline(never)]
pub fn process_set_policy_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let SetPolicyIxData {
        withdrawals,
        asset_policy,
        approver,
        assets,
    } = wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;
    let withdrawals = WithdrawalRule::try_from(withdrawals)?;
    let asset_policy = AssetPolicy::try_from(asset_policy)?;
    if assets.len() > MAX_ASSETS {
        return Err(CustomRingError::InvalidPolicy.into());
    }
    let mut table = [AssetRule {
        mint: [0u8; 32],
        withdrawals: WithdrawalRule::Open,
    }; MAX_ASSETS];
    for (index, asset) in assets.iter().enumerate() {
        // A mint listed twice would let the first entry's rule shadow the
        // second silently.
        if assets[..index]
            .iter()
            .any(|earlier| earlier.mint == asset.mint)
        {
            return Err(CustomRingError::InvalidPolicy.into());
        }
        table[index] = AssetRule {
            mint: asset.mint,
            withdrawals: WithdrawalRule::try_from(asset.withdrawals)?,
        };
    }
    let table = &table[..assets.len()];
    let needs_approver = withdrawals == WithdrawalRule::Approval
        || table
            .iter()
            .any(|asset| asset.withdrawals == WithdrawalRule::Approval);
    let approver = Address::new_from_array(approver);
    if needs_approver && approver == Address::default() {
        return Err(CustomRingError::InvalidPolicy.into());
    }

    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config_account = iter.next_mut("config")?;

    let mut config = load_config_mut(config_account)?;
    if !address_eq(&config.authority, authority.address()) {
        return Err(CustomRingError::UnauthorizedAuthority.into());
    }
    config.set_policy(asset_policy, withdrawals, approver, table);
    Ok(())
}
