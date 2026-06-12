use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

use super::common::{check_record_pda_with_bump, read_record};
use crate::error::{fail, UserRegistryError};

/// Closes the record and refunds rent to the owner. Only allowed before any
/// sync-delegate entry exists.
pub fn process_close(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (head, tail) = accounts.split_at_mut(1);
    let record = &mut head[0];
    let owner = &mut tail[0];

    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let state = read_record(record, program_id)?;
    check_record_pda_with_bump(record, owner.address().as_array(), state.bump, program_id)?;
    if &state.owner != owner.address().as_array() {
        return Err(fail(UserRegistryError::OwnerMismatch));
    }
    if !state.entries.is_empty() {
        return Err(fail(UserRegistryError::RecordNotEmpty));
    }

    let refund = owner
        .lamports()
        .checked_add(record.lamports())
        .ok_or(ProgramError::ArithmeticOverflow)?;
    owner.set_lamports(refund);
    record.close()
}
