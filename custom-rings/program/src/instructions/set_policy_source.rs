use custom_ring_interface::{CustomRingError, SetPolicySourceIxData, SourceSlot};
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_ring_policy::ListId;

use crate::instructions::{
    loader::{load_authorized_config, load_registry_mut},
    policy_shared::curator_source,
    shared::parse,
};

#[inline(never)]
pub fn process_set_policy_source_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: SetPolicySourceIxData = parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("config")?;
    let registry = iter.next_mut("registry")?;
    let curators = iter.remaining_unchecked()?;

    load_authorized_config(program_id, config, authority)?;
    let list_id = ListId::try_from(ix.list_id).map_err(|_| CustomRingError::InvalidListId)?;
    let source = match (ix.source, curators) {
        (0, []) => Address::default(),
        (1, [curator]) => curator_source(program_id, curator)?,
        _ => return Err(CustomRingError::InvalidSource.into()),
    };
    let mut registry = load_registry_mut(program_id, registry)?;
    let mut sources = registry.sources;
    if sources[list_id.slot()].list_id == 0 {
        return Err(CustomRingError::InvalidSource.into());
    }
    sources[list_id.slot()] = SourceSlot {
        list_id: list_id as u8,
        registry: source,
    };
    // The rehashed source map refuses a second distinct curator.
    let rules = registry.rules;
    registry.set_policy(sources, rules, Clock::get()?.slot)?;
    Ok(())
}
