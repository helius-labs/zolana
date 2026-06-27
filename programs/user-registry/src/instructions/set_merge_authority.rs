use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_user_registry_interface::instruction::SetMergeAuthorityData;

use super::common::{check_record_pda_with_bump, read_record, write_record};
use crate::error::{fail, UserRegistryError};

/// Sets the per-user merge authority. Only the record owner may sign;
/// the sync delegate cannot change the merge authority.
pub fn process_set_merge_authority(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: SetMergeAuthorityData,
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

    state.merge_authority = data.authority.map(Into::into);
    write_record(record, &state)
}
