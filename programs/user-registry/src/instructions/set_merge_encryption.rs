use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use spr_user_registry_interface::instruction::SetMergeEncryptionData;

use super::common::{check_record_pda_with_bump, read_record, write_record};
use crate::error::{fail, UserRegistryError};

/// Selects the merge encryption scheme for this record, or disables merging.
/// Only the record owner may sign.
pub fn process_set_merge_encryption(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: SetMergeEncryptionData,
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

    state.merge_encryption = data.scheme;
    write_record(record, &state)
}
