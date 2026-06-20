use borsh::BorshDeserialize;
use pinocchio::{
    cpi::{invoke, invoke_signed, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    sysvars::{rent::Rent, Sysvar},
    AccountView, Address, ProgramResult, Resize,
};
use zolana_user_registry_interface::{UserRecord, USER_RECORD_SEED};

use crate::error::{fail, UserRegistryError};

pub const SYSTEM_PROGRAM_ID: Address = Address::new_from_array([0u8; 32]);

pub fn check_system_program(account: &AccountView) -> Result<(), ProgramError> {
    if account.address() != &SYSTEM_PROGRAM_ID {
        return Err(fail(UserRegistryError::InvalidSystemProgram));
    }
    Ok(())
}

/// CHECK that `record` is the canonical PDA for `owner` and return the bump.
pub fn check_record_pda(
    record: &AccountView,
    owner: &Address,
    program_id: &Address,
) -> Result<u8, ProgramError> {
    let (expected, bump) =
        Address::find_program_address(&[USER_RECORD_SEED, owner.as_ref()], program_id);
    if record.address() != &expected {
        return Err(fail(UserRegistryError::InvalidRecordPda));
    }
    Ok(bump)
}

/// CHECK `record` against a stored bump.
pub fn check_record_pda_with_bump(
    record: &AccountView,
    owner: &[u8; 32],
    bump: u8,
    program_id: &Address,
) -> Result<(), ProgramError> {
    let expected = Address::derive_address(
        &[USER_RECORD_SEED, owner.as_slice()],
        Some(bump),
        program_id,
    );
    if record.address() != &expected {
        return Err(fail(UserRegistryError::InvalidRecordPda));
    }
    Ok(())
}

/// Deserialize record and CHECK ownership, is_writable, discriminator
pub fn read_record(record: &AccountView, program_id: &Address) -> Result<UserRecord, ProgramError> {
    if !record.owned_by(program_id) || !record.is_writable() {
        return Err(fail(UserRegistryError::InvalidRecordAccount));
    }
    let data = record.try_borrow()?;
    match data.split_first() {
        Some((&UserRecord::DISCRIMINATOR, body)) => UserRecord::deserialize(&mut &*body)
            .map_err(|_| fail(UserRegistryError::InvalidRecordAccount)),
        _ => Err(fail(UserRegistryError::InvalidRecordAccount)),
    }
}

pub fn write_record(record: &mut AccountView, state: &UserRecord) -> ProgramResult {
    let body = borsh::to_vec(state).map_err(|_| ProgramError::InvalidAccountData)?;
    let needed = UserRecord::DISCRIMINATOR_LEN + body.len();
    let mut data = record.try_borrow_mut()?;
    if data.len() < needed {
        return Err(ProgramError::AccountDataTooSmall);
    }
    data[0] = UserRecord::DISCRIMINATOR;
    data[1..needed].copy_from_slice(&body);
    Ok(())
}

pub fn create_record_account(
    record: &AccountView,
    payer: &AccountView,
    owner: &Address,
    bump: u8,
    space: usize,
    program_id: &Address,
) -> ProgramResult {
    let required = Rent::get()?.try_minimum_balance(space)?;
    let bump_seed = [bump];
    let seeds = [
        Seed::from(USER_RECORD_SEED),
        Seed::from(owner.as_ref()),
        Seed::from(&bump_seed[..]),
    ];
    let signer = Signer::from(&seeds[..]);

    let top_up = required.saturating_sub(record.lamports());
    if top_up > 0 {
        system_transfer(payer, record, top_up)?;
    }

    let mut allocate_data = [0u8; 12];
    allocate_data[0] = 8;
    allocate_data[4..12].copy_from_slice(&(space as u64).to_le_bytes());
    let metas = [InstructionAccount::writable_signer(record.address())];
    let instruction = InstructionView {
        program_id: &SYSTEM_PROGRAM_ID,
        accounts: &metas,
        data: &allocate_data,
    };
    invoke_signed::<1, _>(&instruction, &[record], std::slice::from_ref(&signer))?;

    let mut assign_data = [0u8; 36];
    assign_data[0] = 1;
    assign_data[4..36].copy_from_slice(program_id.as_ref());
    let metas = [InstructionAccount::writable_signer(record.address())];
    let instruction = InstructionView {
        program_id: &SYSTEM_PROGRAM_ID,
        accounts: &metas,
        data: &assign_data,
    };
    invoke_signed::<1, _>(&instruction, &[record], &[signer])
}

pub fn system_transfer(from: &AccountView, to: &AccountView, lamports: u64) -> ProgramResult {
    let mut data = [0u8; 12];
    data[0] = 2;
    data[4..12].copy_from_slice(&lamports.to_le_bytes());
    let metas = [
        InstructionAccount::writable_signer(from.address()),
        InstructionAccount::writable(to.address()),
    ];
    let instruction = InstructionView {
        program_id: &SYSTEM_PROGRAM_ID,
        accounts: &metas,
        data: &data,
    };
    invoke::<2, _>(&instruction, &[from, to])
}

pub fn grow_record(
    record: &mut AccountView,
    payer: &AccountView,
    new_space: usize,
) -> ProgramResult {
    let required = Rent::get()?.try_minimum_balance(new_space)?;
    let top_up = required.saturating_sub(record.lamports());
    if top_up > 0 {
        system_transfer(payer, record, top_up)?;
    }
    record.resize(new_space)
}
