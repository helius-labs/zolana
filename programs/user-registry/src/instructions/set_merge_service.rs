use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_user_registry_interface::instruction::SetMergeServiceData;

use super::common::{check_record_pda_with_bump, read_record, write_record};
use crate::error::{fail, UserRegistryError};

/// Toggles the per-user merge-service opt-in. Only the record owner may sign;
/// the sync delegate cannot opt the owner in or out.
pub fn process_set_merge_service(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: SetMergeServiceData,
) -> ProgramResult {
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

    if signer.address().as_array() != &state.owner {
        return Err(fail(UserRegistryError::UnauthorizedSigner));
    }

    state.merge_service = data.enabled;
    write_record(record, &state)
}
