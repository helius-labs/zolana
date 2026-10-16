use custom_ring_interface::{CustomRingError, PolicyConfig, SetPolicySourceIxData, SourceSlot};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_ring_policy::ListId;

use crate::instructions::{
    loader::{load_authorized_config, load_curator_registry, load_mut},
    policy_shared::repin,
    shared::parse,
};

/// Only a list the stored table references has a slot to re-point.
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
    let policy_config = iter.next_mut("policy_config")?;
    let curators = iter.remaining_unchecked()?;

    load_authorized_config(program_id, config, authority)?;
    let mut live = load_mut::<PolicyConfig>(program_id, policy_config)?;
    let list_id = ListId::try_from(ix.list_id).map_err(|_| CustomRingError::InvalidListId)?;
    let mut sources = live.sources;
    if sources[list_id.slot()].list_id == 0 {
        return Err(CustomRingError::InvalidSource.into());
    }
    let registry = match (ix.source, curators) {
        (0, []) => Address::default(),
        (1, [curator]) => load_curator_registry(curator)?,
        _ => return Err(CustomRingError::InvalidSource.into()),
    };
    sources[list_id.slot()] = SourceSlot {
        list_id: list_id as u8,
        registry,
    };
    // The repin rebuilds the source map, which refuses a second distinct curator.
    repin(&mut live, &sources)
}
