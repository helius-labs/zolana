use pinocchio::{AccountView, Address, ProgramResult};

use crate::instructions::{loader::validate_spp_program, shared::cpi_spp_signed};

/// Forwards an SPP ring transition with the ring authority signature.
#[inline(never)]
pub fn process_spp_forward_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    validate_spp_program(accounts)?;
    cpi_spp_signed(program_id, accounts, data)
}
