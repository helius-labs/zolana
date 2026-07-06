pub mod error;
pub mod instructions;
pub mod verifying_keys;

use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address, ProgramResult};

use crate::instructions::{
    process_cancel, process_create_swap, process_fill, process_fill_verifiable_encryption,
};

pub mod tag {
    pub const CREATE_SWAP: u8 = 2;
    pub const FILL: u8 = 3;
    pub const CANCEL: u8 = 4;
    pub const FILL_VERIFIABLE_ENCRYPTION: u8 = 5;
}

pub const ESCROW_AUTHORITY_PDA_SEED: &[u8] = b"escrow_authority";

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

pinocchio::address::declare_id!("US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx");

pub const SWAP_PROGRAM_ID: Address = crate::ID;

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
        tag::CREATE_SWAP => process_create_swap(accounts, ix_data),
        tag::FILL => process_fill(accounts, ix_data),
        tag::CANCEL => process_cancel(accounts, ix_data),
        tag::FILL_VERIFIABLE_ENCRYPTION => process_fill_verifiable_encryption(accounts, ix_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
