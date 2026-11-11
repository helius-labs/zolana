use pinocchio::{
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, Address, ProgramResult, Resize,
};
use spr_user_registry_interface::{instruction::SetData, UserRecord};

use super::common::{
    check_record_pda_with_bump, check_system_program, read_record, system_transfer,
};
use crate::error::{fail, UserRegistryError};

/// Replaces the record's data and resizes the account to fit it. Previous data
/// is not kept on chain; indexers recover it from the earlier `set_data`
/// instruction. Lamports freed by shrinking stay in the record.
#[inline(never)]
pub fn process_set_data_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    ix: SetData,
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

    // Empty data drops the length prefix, restoring the header-only layout.
    let new_size = if ix.data.is_empty() {
        UserRecord::SIZE
    } else {
        UserRecord::SIZE + UserRecord::DATA_LEN_SIZE + ix.data.len()
    };
    let required = Rent::get()?.try_minimum_balance(new_size)?;
    let top_up = required.saturating_sub(record_account.lamports());
    if top_up > 0 {
        system_transfer(rent_payer_account, record_account, top_up)?;
    }
    record_account.resize(new_size)?;
    if ix.data.is_empty() {
        return Ok(());
    }
    let data_len = u32::try_from(ix.data.len())
        .map_err(|_| fail(UserRegistryError::InvalidInstructionData))?;
    let mut bytes = record_account.try_borrow_mut()?;
    let (length_bytes, data_bytes) = bytes
        .get_mut(UserRecord::SIZE..)
        .and_then(|extension| extension.split_at_mut_checked(UserRecord::DATA_LEN_SIZE))
        .ok_or_else(|| fail(UserRegistryError::InvalidRecordAccount))?;
    length_bytes.copy_from_slice(&data_len.to_le_bytes());
    data_bytes.copy_from_slice(&ix.data);
    Ok(())
}
