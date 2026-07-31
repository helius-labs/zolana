use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_user_registry_interface::{instruction::RegisterData, UserRecord};

use super::{
    common::{check_record_pda, check_system_program, create_record_account, write_record},
    p256_proof::verify_p256_key_binding,
};
use crate::error::{fail, UserRegistryError};

/// Creates a per-owner record with its shielded keys and merging disabled.
pub fn process_register(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: RegisterData,
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (head, tail) = accounts.split_at_mut(1);
    let record = &mut head[0];
    let owner = &tail[0];
    let system_program = &tail[1];

    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !record.is_writable() {
        return Err(fail(UserRegistryError::InvalidRecordAccount));
    }
    check_system_program(system_program)?;

    let owner_address = *owner.address();
    let bump = check_record_pda(record, &owner_address, program_id)?;

    if let Some(owner_p256) = &data.owner_p256 {
        let instructions = tail.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;
        verify_p256_key_binding(instructions, record.address(), &owner_address, owner_p256)?;
    }

    if record.owned_by(program_id) || !record.is_data_empty() {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    create_record_account(
        record,
        owner,
        &owner_address,
        bump,
        UserRecord::SIZE,
        program_id,
    )?;

    let state = UserRecord {
        owner: (*owner_address.as_array()).into(),
        bump,
        owner_p256: data.owner_p256,
        nullifier_pubkey: data.nullifier_pubkey,
        viewing_pubkey: data.viewing_pubkey,
        merging_enabled: false,
    };
    write_record(record, &state)
}
