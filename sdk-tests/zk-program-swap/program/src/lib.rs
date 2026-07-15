pub mod error;
pub mod instructions;
pub mod verifying_keys;

use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address, ProgramResult};

use crate::instructions::{
    process_cancel_ix, process_make_ix, process_take_ix, process_take_verifiable_encryption_ix,
};

pub mod tag {
    pub const MAKE: u8 = 2;
    pub const TAKE: u8 = 3;
    pub const CANCEL: u8 = 4;
    pub const TAKE_VERIFIABLE_ENCRYPTION: u8 = 5;
}

pub const ORDER_AUTHORITY_PDA_SEED: &[u8] = b"order_authority";

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

pinocchio::address::declare_id!("US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx");

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if !address_eq(program_id, &crate::ID) {
        return Err(ProgramError::IncorrectProgramId);
    }

    let (ix_tag, ix_data) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match *ix_tag {
        tag::MAKE => process_make_ix(accounts, ix_data),
        tag::TAKE => process_take_ix(accounts, ix_data),
        tag::CANCEL => process_cancel_ix(accounts, ix_data),
        tag::TAKE_VERIFIABLE_ENCRYPTION => process_take_verifiable_encryption_ix(accounts, ix_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
