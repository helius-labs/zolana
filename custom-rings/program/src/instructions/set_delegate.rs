use custom_ring_interface::Delegate;
use pinocchio::{
    cpi::{Seed, Signer},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_delegate, UpgradeAuthorityCheck},
        shared::PdaCheck,
    },
    state::DelegateInitParams,
};

#[inline(never)]
pub fn process_set_delegate_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let delegate: [u8; 32] = data
        .try_into()
        .map_err(|_| CustomRingError::InvalidInstructionData)?;
    if delegate == [0; 32] {
        return Err(CustomRingError::InvalidDelegate.into());
    }

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let delegate_account = iter.next_mut("delegate_pda")?;
    let system_program = iter.next_account("system_program")?;
    let program = iter.next_account("program")?;
    let program_data = iter.next_account("program_data")?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(CustomRingError::InvalidSystemProgram.into());
    }
    // 1. Reserve delegate appointment to the upgrade authority.
    UpgradeAuthorityCheck {
        program_id,
        authority,
        program,
        program_data,
    }
    .verify()?;
    // 2. Permit only the first appointment at the canonical delegate address.
    if load_delegate(program_id, delegate_account)?.is_some() {
        return Err(CustomRingError::DelegateAlreadySet.into());
    }

    let bump = PdaCheck {
        program_id,
        address: delegate_account.address(),
        seeds: &[Delegate::SEED],
        mismatch: CustomRingError::InvalidDelegate,
    }
    .verify()?;
    let bump_seed = [bump];
    let seeds = [Seed::from(Delegate::SEED), Seed::from(bump_seed.as_ref())];
    pinocchio_system::create_account_with_minimum_balance_signed(
        delegate_account,
        Delegate::SIZE,
        program_id,
        payer,
        None,
        &[Signer::from(seeds.as_ref())],
    )?;
    DelegateInitParams {
        delegate: Address::new_from_array(delegate),
        bump,
    }
    .init(delegate_account)
}
