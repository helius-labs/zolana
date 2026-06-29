use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_user_registry_interface::{
    instruction::RotateSyncDelegateKeyData, SyncDelegateEntry, UserRecord,
};

use super::common::{
    check_record_pda_with_bump, check_system_program, grow_record, read_record, write_record,
};
use crate::error::{fail, UserRegistryError};

/// Appends a new sync-delegate entry without changing the sync delegate address.
pub fn process_rotate_sync_delegate_key(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: RotateSyncDelegateKeyData,
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (head, tail) = accounts.split_at_mut(1);
    let record = &mut head[0];
    let sync_delegate = &tail[0];
    let system_program = &tail[1];

    if !sync_delegate.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    check_system_program(system_program)?;

    let mut state = read_record(record, program_id)?;
    check_record_pda_with_bump(record, state.owner.as_array(), state.bump, program_id)?;
    if state.sync_delegate.as_ref() != Some(sync_delegate.address().as_array()) {
        return Err(fail(UserRegistryError::InvalidSyncDelegate));
    }
    let delegate = *sync_delegate.address().as_array();

    state.entries.push(SyncDelegateEntry {
        delegate,
        sync_pubkey: data.sync_pubkey,
        viewing_pubkey: data.viewing_pubkey,
        created_at: Clock::get()?.unix_timestamp,
    });

    grow_record(
        record,
        sync_delegate,
        UserRecord::space_for(state.entries.len()),
    )?;
    write_record(record, &state)
}
