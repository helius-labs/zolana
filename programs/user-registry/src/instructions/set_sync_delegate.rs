use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_interface::user_registry::instruction::SetSyncDelegateData;

use super::common::{
    check_record_pda_with_bump, check_system_program, grow_record, read_record, write_record,
};
use crate::{
    error::{fail, UserRegistryError},
    state::{validate_p256_pubkey, SyncDelegateEntry, UserRecord},
};

/// Appoints or replaces the sync delegate and appends a sync-delegate entry.
pub fn process_set_sync_delegate(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: SetSyncDelegateData,
) -> ProgramResult {
    validate_p256_pubkey(&data.sync_pubkey)?;
    validate_p256_pubkey(&data.viewing_pubkey)?;

    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (head, tail) = accounts.split_at_mut(1);
    let record = &mut head[0];
    let owner = &tail[0];
    let system_program = &tail[1];

    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    check_system_program(system_program)?;

    let mut state = read_record(record, program_id)?;
    check_record_pda_with_bump(record, owner.address().as_array(), state.bump, program_id)?;
    if &state.owner != owner.address().as_array() {
        return Err(fail(UserRegistryError::OwnerMismatch));
    }

    state.sync_delegate = Some(data.sync_delegate);
    state.entries.push(SyncDelegateEntry {
        sync_pubkey: data.sync_pubkey,
        viewing_pubkey: data.viewing_pubkey,
        created_at: Clock::get()?.unix_timestamp,
    });

    grow_record(record, owner, UserRecord::space_for(state.entries.len()))?;
    write_record(record, &state)
}
