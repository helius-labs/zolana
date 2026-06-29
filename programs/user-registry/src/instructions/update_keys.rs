use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_user_registry_interface::instruction::UpdateKeysData;

use super::common::{check_record_pda_with_bump, read_record, write_record};
use crate::error::{fail, UserRegistryError};

/// Updates the shielded keys stored in an existing user record.
pub fn process_update_keys(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: UpdateKeysData,
) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (head, tail) = accounts.split_at_mut(1);
    let record = &mut head[0];
    let owner = &tail[0];

    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut state = read_record(record, program_id)?;
    check_record_pda_with_bump(record, state.owner.as_array(), state.bump, program_id)?;
    if state.owner.as_array() != owner.address().as_array() {
        return Err(fail(UserRegistryError::OwnerMismatch));
    }

    state.owner_p256 = data.owner_p256;
    state.nullifier_pubkey = data.nullifier_pubkey;
    state.viewing_pubkey = data.viewing_pubkey;
    write_record(record, &state)
}
