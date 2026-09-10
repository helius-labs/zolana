use bytemuck::from_bytes_mut;
use custom_ring_interface::{PolicyConfig, SetPolicySourceIxData, SourceSlot};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_ring_policy::ListId;

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_authorized_config, load_policy_config},
        policy_shared::{load_curator_policy_config, namespace_pda, repin, Repin},
    },
};

/// Only a list the stored table references has a slot to re-point.
#[inline(never)]
pub fn process_set_policy_source_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: SetPolicySourceIxData =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;

    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("config")?;
    let policy_config = iter.next_mut("policy_config")?;
    let curators = iter.remaining_unchecked()?;

    load_authorized_config(program_id, config, authority)?;
    let (entries_tree, mut sources) = {
        let stored = load_policy_config(program_id, policy_config)?;
        (stored.entries_tree, stored.sources)
    };

    let list_id = ListId::try_from(ix.list_id).map_err(|_| CustomRingError::InvalidListId)?;
    let index = list_id.slot();
    if sources[index].list_id == 0 {
        return Err(CustomRingError::InvalidSource.into());
    }
    let entries = match (ix.source, curators) {
        (0, []) => namespace_pda(program_id)?.0,
        (1, [curator]) => load_curator_policy_config(curator, &entries_tree)?
            .source_for(list_id)
            .ok_or(CustomRingError::CuratorSourceMissing)?,
        _ => return Err(CustomRingError::InvalidSource.into()),
    };
    sources[index] = SourceSlot {
        list_id: list_id as u8,
        namespace: entries,
    };

    let mut data = policy_config.try_borrow_mut()?;
    let live: &mut PolicyConfig = from_bytes_mut(&mut data);
    repin(live, Repin::Sources(&sources))
}
