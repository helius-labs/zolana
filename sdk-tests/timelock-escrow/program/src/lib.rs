#[cfg(any(feature = "circuits", feature = "wasm"))]
pub mod circuits;
#[cfg(feature = "circuits")]
pub mod client;
pub mod error;
pub mod instructions;
pub mod zk {
    zolana_macros::include_zk_programs!();
}

use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address, ProgramResult};

use crate::instructions::{process_escrow_ix, process_withdraw_ix};

pub mod tag {
    pub const ESCROW: u8 = 0;
    pub const WITHDRAW: u8 = 1;
}

pub const ESCROW_AUTHORITY_PDA_SEED: &[u8] = b"escrow_authority";

pub fn escrow_authority_seeds(creator: &Address) -> [&[u8]; 2] {
    [ESCROW_AUTHORITY_PDA_SEED, creator.as_array()]
}

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
