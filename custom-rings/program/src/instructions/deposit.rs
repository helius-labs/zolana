use pinocchio::{AccountView, Address, ProgramResult};

use crate::instructions::{loader::validate_spp_program, shared::cpi_spp_signed};

/// Proofless forwarder for SPP `RING_DEPOSIT`.
///
/// Deposit amounts are public on-chain, so the ring has no statement to prove
/// here and only lends its `ring_auth` signature. `data` still carries the
/// leading tag byte: the client builds the instruction with the interface's
/// `RingDeposit` builder, which already emits SPP's tag 14 and lays the accounts
/// out exactly as SPP's deposit loader expects, so the forward is verbatim and
/// nothing is re-tagged.
#[inline(never)]
pub fn process_deposit_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    validate_spp_program(accounts)?;
    cpi_spp_signed(program_id, accounts, data)
}
