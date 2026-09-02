use bytemuck::from_bytes_mut;
use custom_ring_interface::{PolicyConfig, SetPolicySourceIxData, SourceSlot};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_ring_policy::ListId;

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_authorized_config, load_policy_config},
        policy_shared::{
            compute_policy_hash, load_curator_policy_config, namespace_pda, verify_policy_hash,
        },
    },
};

/// The stored hash must be reproducible from the stored map under the
/// compiled table before anything is written, a table upgrade stays fail
/// closed and only `create_policy` pins a table.
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
    let stored: PolicyConfig = *load_policy_config(program_id, policy_config)?;

    verify_policy_hash(&stored.sources, &stored.policy_hash)?;

    let list_id = ListId::try_from(ix.list_id).map_err(|_| CustomRingError::InvalidListId)?;
    let index = list_id.slot();
    if stored.sources[index].list_id == 0 {
        return Err(CustomRingError::InvalidSource.into());
    }
    let entries = match (ix.source, curators) {
        (0, []) => namespace_pda(program_id)?.0,
        (1, [curator]) => load_curator_policy_config(curator, &stored.entries_tree)?
            .source_for(list_id)
            .ok_or(CustomRingError::CuratorSourceMissing)?,
        _ => return Err(CustomRingError::InvalidSource.into()),
    };

    let mut sources = stored.sources;
    sources[index] = SourceSlot {
        list_id: list_id as u8,
        namespace: entries,
    };
    let policy_hash = compute_policy_hash(&sources)?;

    let mut data = policy_config
        .try_borrow_mut()
        .map_err(|_| CustomRingError::PolicyConfigNotInitialized)?;
    let live: &mut PolicyConfig = from_bytes_mut(&mut data);
    live.sources = sources;
    live.policy_hash = policy_hash;
    Ok(())
}
