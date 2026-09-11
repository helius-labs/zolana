use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::instructions::{
    cosign::{require_cosigner, Demand},
    loader::validate_spp_program,
    shared::cpi_spp_signed,
};

/// Forwards an SPP ring transition with the ring authority signature, the
/// `[cosigner_pda, cosigner]` prefix is the ring's and stays behind.
#[inline(never)]
pub fn process_spp_forward_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
    demand: &Demand,
) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let cosigner_account = iter.next_account("cosigner_pda")?;
    let cosigner = iter.next_account("cosigner")?;
    let spp_accounts = iter.remaining_mut()?;
    validate_spp_program(spp_accounts)?;
    require_cosigner(program_id, cosigner_account, cosigner, demand)?;
    cpi_spp_signed(program_id, spp_accounts, data)
}
