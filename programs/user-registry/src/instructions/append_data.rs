use pinocchio::{
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, Address, ProgramResult, Resize,
};
use spr_user_registry_interface::{instruction::AppendData, UserRecord};

use super::common::{
    check_record_pda_with_bump, check_system_program, read_record, system_transfer,
};
use crate::error::{fail, UserRegistryError};

#[inline(never)]
pub fn process_append_data_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    ix: AppendData,
) -> ProgramResult {
    let [record_account, owner_account, rent_payer_account, system_program_account, ..] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !owner_account.is_signer() || !rent_payer_account.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    check_system_program(system_program_account)?;
    let record = read_record(record_account, program_id)?;
    check_record_pda_with_bump(
        record_account,
        record.owner.as_array(),
        record.bump,
        program_id,
    )?;
    if record.owner.as_array() != owner_account.address().as_array() {
        return Err(fail(UserRegistryError::OwnerMismatch));
    }
    if ix.data.is_empty() {
        return Ok(());
    }
    let old_length = {
        let bytes = record_account.try_borrow()?;
        UserRecord::additional_data(&bytes)
            .map_err(|_| fail(UserRegistryError::InvalidRecordAccount))?
            .len()
    };
    let new_length = old_length
        .checked_add(ix.data.len())
        .and_then(|length| u32::try_from(length).ok())
        .ok_or(ProgramError::InvalidRealloc)?;
    let new_size = UserRecord::SIZE
        .checked_add(UserRecord::DATA_LEN_SIZE)
        .and_then(|size| size.checked_add(new_length as usize))
        .ok_or(ProgramError::InvalidRealloc)?;
    let required = Rent::get()?.try_minimum_balance(new_size)?;
    let top_up = required.saturating_sub(record_account.lamports());
    if top_up > 0 {
        system_transfer(rent_payer_account, record_account, top_up)?;
    }
    record_account.resize(new_size)?;
    let mut bytes = record_account.try_borrow_mut()?;
    let extension = bytes
        .get_mut(UserRecord::SIZE..)
        .ok_or(ProgramError::InvalidAccountData)?;
    let (length_bytes, data_bytes) = extension.split_at_mut(UserRecord::DATA_LEN_SIZE);
    length_bytes.copy_from_slice(&new_length.to_le_bytes());
    data_bytes
        .get_mut(old_length..)
        .ok_or(ProgramError::InvalidAccountData)?
        .copy_from_slice(&ix.data);
    Ok(())
}
