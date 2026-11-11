use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use spr_user_registry_interface::instruction::RotateNullifierKeyData;

use super::common::{check_record_pda_with_bump, read_record, write_record};
use crate::error::{fail, UserRegistryError};

#[inline(always)]
pub fn process_rotate_nullifier_key_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    ix: RotateNullifierKeyData,
) -> ProgramResult {
    let [record_account, owner_account, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !owner_account.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let mut record = read_record(record_account, program_id)?;
    check_record_pda_with_bump(
        record_account,
        record.owner.as_array(),
        record.bump,
        program_id,
    )?;
    if record.owner.as_array() != owner_account.address().as_array() {
        return Err(fail(UserRegistryError::OwnerMismatch));
    }
    record.nullifier_pubkey = ix.nullifier_pubkey;
    write_record(record_account, &record)
}
