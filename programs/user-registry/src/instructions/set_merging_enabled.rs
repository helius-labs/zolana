use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use rings_user_registry_interface::instruction::SetMergingEnabledData;

use super::common::{check_record_pda_with_bump, read_record, write_record};
use crate::error::{fail, UserRegistryError};

/// Enables or disables merging for this record. Only the record owner may sign;
/// the sync delegate cannot change the merging opt-in.
pub fn process_set_merging_enabled(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: SetMergingEnabledData,
) -> ProgramResult {
    let (record, tail) = accounts
        .split_first_mut()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let signer = tail.first().ok_or(ProgramError::NotEnoughAccountKeys)?;

    if !signer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut state = read_record(record, program_id)?;
    check_record_pda_with_bump(record, state.owner.as_array(), state.bump, program_id)?;

    if signer.address().as_array() != state.owner.as_array() {
        return Err(fail(UserRegistryError::UnauthorizedSigner));
    }

    state.merging_enabled = data.enabled;
    write_record(record, &state)
}
