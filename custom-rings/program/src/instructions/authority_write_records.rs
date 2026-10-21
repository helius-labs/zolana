use custom_ring_interface::{AuthorityWriteRecordsIxData, PendingApplication, RecordWriteData};
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;

use crate::instructions::{
    apply_records::verify_application,
    loader::{load_authorized_config, load_queue_mut, load_registry_mut},
};

/// Applies every pending write together with the authority's.
#[inline(never)]
pub fn process_authority_write_records_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix = AuthorityWriteRecordsIxData::parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("config")?;
    let registry = iter.next_mut("registry")?;
    let queue = iter.next_mut("queue")?;

    load_authorized_config(program_id, config, authority)?;
    let entries = ix
        .writes
        .iter()
        .map(RecordWriteData::entry)
        .collect::<Result<Vec<_>, _>>()?;
    let slot = Clock::get()?.slot;
    let mut registry = load_registry_mut(program_id, registry)?;
    let mut queue = load_queue_mut(program_id, queue)?;
    queue.admit_authority_writes(entries.len() as u64)?;
    for entry in &entries {
        queue.push(entry, slot)?;
    }
    let application = PendingApplication {
        registry: &mut registry,
        queue: &mut queue,
    };
    verify_application(&application, ix.apply)?;
    application.settle_authority(ix.apply, slot);
    Ok(())
}
