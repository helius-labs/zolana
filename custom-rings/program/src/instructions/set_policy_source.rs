use bytemuck::from_bytes_mut;
use custom_ring_interface::{PolicyConfig, PolicySourceSlot, SetPolicySourceIxData, POLICY};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_ring_policy::RecordKind;

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_authorized_config, load_policy_config},
        policy_shared::{kind_owners, load_curator_policy_config, records_pda},
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

    if POLICY
        .hash(&kind_owners(&stored.sources)?)
        .map_err(|_| CustomRingError::HashingFailed)?
        != stored.policy_hash
    {
        return Err(CustomRingError::PolicyHashMismatch.into());
    }

    let kind = RecordKind::try_from(ix.kind).map_err(|_| CustomRingError::InvalidRecordKind)?;
    let index = kind as usize - 1;
    if stored.sources[index].kind == 0 {
        return Err(CustomRingError::InvalidPolicySource.into());
    }
    let records = match (ix.source, curators) {
        (0, []) => records_pda(program_id)?.0,
        (1, [curator]) => load_curator_policy_config(curator, &stored.records_tree)?
            .source_for(kind as u8)
            .ok_or(CustomRingError::CuratorSourceMissing)?,
        _ => return Err(CustomRingError::InvalidPolicySource.into()),
    };

    let mut sources = stored.sources;
    sources[index] = PolicySourceSlot {
        kind: kind as u8,
        records,
    };
    let policy_hash = POLICY
        .hash(&kind_owners(&sources)?)
        .map_err(|_| CustomRingError::HashingFailed)?;

    let mut data = policy_config
        .try_borrow_mut()
        .map_err(|_| CustomRingError::PolicyConfigNotInitialized)?;
    let live: &mut PolicyConfig = from_bytes_mut(&mut data);
    live.sources = sources;
    live.policy_hash = policy_hash;
    Ok(())
}
