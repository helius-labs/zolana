use custom_ring_interface::{CustomRingError, PolicyTableIxData};
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

#[inline(never)]
pub fn process_create_policy_ix(
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

    // 1. Only a policy ring takes a table, its first one here.
    if !load_authorized_config(program_id, config, authority)?.has_policy() {
        return Err(CustomRingError::PolicyOnAuditOnlyRing.into());
    }
    let mut registry = load_registry_mut(program_id, registry)?;
    if registry.policy_hash().is_ok() {
        return Err(CustomRingError::PolicyAlreadySet.into());
    }
    // 2. Sources name exactly the lists the rules reference.
    let bound = TableBinding {
        program_id,
        table: &ix,
        curators,
    }
    .bind()?;
    // 3. The pinned hash binds every later policy proof.
    registry.set_policy(bound.sources, bound.rules, Clock::get()?.slot)?;
    Ok(())
}
