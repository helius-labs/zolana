use custom_ring_interface::{
    key_catalog::RingCircuit, ApplyRecordsIxData, CustomRingError, PendingApplication,
};
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;

use crate::instructions::{
    loader::{load_queue_mut, load_registry_mut},
    verifier::{ring_key, RingProof},
};

/// Permissionless once due and once per delay, the floor stays.
#[inline(never)]
pub fn process_apply_records_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix = ApplyRecordsIxData::parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let registry = iter.next_mut("registry")?;
    let queue = iter.next_mut("queue")?;

    let slot = Clock::get()?.slot;
    let mut registry = load_registry_mut(program_id, registry)?;
    let mut queue = load_queue_mut(program_id, queue)?;
    queue.apply_due(slot)?;
    let application = PendingApplication {
        registry: &mut registry,
        queue: &mut queue,
    };
    verify_application(&application, ix)?;
    application.settle_permissionless(ix, slot);
    Ok(())
}

pub(crate) fn verify_application(
    application: &PendingApplication<'_>,
    apply: &ApplyRecordsIxData,
) -> ProgramResult {
    let statement = application.statement(apply);
    RingProof {
        proof: &apply.proof,
        statement: statement.hash().map_err(CustomRingError::from)?,
        key: ring_key(RingCircuit::apply_records(statement.count))?,
    }
    .verify()
}
