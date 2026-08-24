mod error;
mod processor;
mod wire;

use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address, ProgramResult};

const CREATE: u8 = 0;
const UPDATE: u8 = 1;

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

pinocchio::address::declare_id!("3iquabFuqdShEfa2E1DXFwVS2zpb4YSucJCFZkJqKZq3");

#[inline(never)]
pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if !address_eq(program_id, &ID) {
        return Err(ProgramError::IncorrectProgramId);
    }
    let (tag, data) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match *tag {
        CREATE => processor::process_create(accounts, data),
        UPDATE => processor::process_update(accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
