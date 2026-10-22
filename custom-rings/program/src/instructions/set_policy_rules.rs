use custom_ring_interface::PolicyTableIxData;
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;

use crate::instructions::{
    loader::{load_authorized_config, load_registry_mut},
    policy_shared::TableBinding,
    shared::parse,
};

/// Takes effect at once.
#[inline(never)]
pub fn process_set_policy_rules_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: PolicyTableIxData = parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("config")?;
    let registry = iter.next_mut("registry")?;
    let curators = iter.remaining_unchecked()?;

    // 1. The authority replaces a table `CreatePolicy` set.
    load_authorized_config(program_id, config, authority)?;
    let mut registry = load_registry_mut(program_id, registry)?;
    registry.policy_hash()?;
    // 2. Sources name exactly the lists the rules reference.
    let bound = TableBinding {
        program_id,
        table: &ix,
        curators,
    }
    .bind()?;
    // 3. The repinned hash refuses every proof over the old table.
    registry.set_policy(bound.sources, bound.rules, Clock::get()?.slot)?;
    Ok(())
}
