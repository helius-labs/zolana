pub mod error;
pub mod instructions;
pub mod state;

use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address, ProgramResult};

use crate::instructions::{process_create_ix, process_update_ix};

pub mod tag {
    pub const CREATE: u8 = 0;
    pub const UPDATE: u8 = 1;
}

pub const ACCOUNT_PDA_SEED: &[u8] = b"compressed-account";

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

pinocchio::address::declare_id!("3iquabFuqdShEfa2E1DXFwVS2zpb4YSucJCFZkJqKZq3");

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if !address_eq(program_id, &ID) {
        return Err(ProgramError::IncorrectProgramId);
    }

    let (ix_tag, ix_data) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match *ix_tag {
        tag::CREATE => process_create_ix(accounts, ix_data),
        tag::UPDATE => process_update_ix(accounts, ix_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
