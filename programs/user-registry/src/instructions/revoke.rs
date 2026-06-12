use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

use super::common::{check_record_pda_with_bump, read_record, write_record};
use crate::error::{fail, UserRegistryError};

/// Clears the active sync delegate. Entry history is preserved.
pub fn process_revoke(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (head, tail) = accounts.split_at_mut(1);
    let record = &mut head[0];
    let signer = &tail[0];

    if !signer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut state = read_record(record, program_id)?;
    check_record_pda_with_bump(record, &state.owner, state.bump, program_id)?;

    let signer_key = signer.address().as_array();
    let authorized =
        signer_key == &state.owner || state.sync_delegate.as_ref() == Some(signer_key);
    if !authorized {
        return Err(fail(UserRegistryError::UnauthorizedSigner));
    }
    if state.sync_delegate.is_none() {
        return Err(fail(UserRegistryError::SyncDelegateNotSet));
    }

    state.sync_delegate = None;
    write_record(record, &state)
}
