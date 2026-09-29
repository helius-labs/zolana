pub mod error;
pub mod instructions;
pub mod spp;
pub mod verifying_keys;

use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address, ProgramResult};

use crate::instructions::{process_escrow_ix, process_withdraw_ix};

pub mod tag {
    pub const ESCROW: u8 = 0;
    pub const WITHDRAW: u8 = 1;
}

pub const ESCROW_AUTHORITY_PDA_SEED: &[u8] = b"escrow_authority";

pub const ESCROW_OWNER_HASH: [u8; 32] = [
    8, 76, 150, 82, 13, 75, 195, 86, 129, 30, 133, 59, 111, 138, 189, 249, 149, 87, 82, 67, 176,
    68, 41, 3, 84, 121, 51, 211, 39, 191, 231, 173,
];

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

pinocchio::address::declare_id!("2ehy1rrRKT3KEVNN6pLmHeiUedwazPZezXXhwaLjCt5G");

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
        tag::ESCROW => process_escrow_ix(accounts, ix_data),
        tag::WITHDRAW => process_withdraw_ix(accounts, ix_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
