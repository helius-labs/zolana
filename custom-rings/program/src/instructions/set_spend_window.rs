use custom_ring_interface::{SetSpendWindowIxData, SpendWindow};
use pinocchio::{
    cpi::{Seed, Signer},
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_authorized_config, load_spend_window},
        shared::PdaCheck,
    },
    state::SpendWindowInitParams,
};

/// Replacing an existing window restarts its counters.
#[inline(never)]
pub fn process_set_spend_window_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let SetSpendWindowIxData {
        mint,
        window_slots,
        deposit_cap,
        withdrawal_cap,
    } = wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;
    if window_slots == 0 {
        return Err(CustomRingError::InvalidSpendWindow.into());
    }

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config_account = iter.next_account("config")?;
    let window_account = iter.next_mut("window")?;
    let system_program = iter.next_account("system_program")?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(CustomRingError::InvalidSystemProgram.into());
    }
    load_authorized_config(program_id, config_account, authority)?;

    let mint = Address::new_from_array(mint);
    let slot = Clock::get()?.slot;
    let existing = load_spend_window(program_id, window_account, &mint)?.map(|window| window.bump);
    let params = |bump| SpendWindowInitParams {
        mint,
        window_slots,
        deposit_cap,
        withdrawal_cap,
        window_start_slot: slot - slot % window_slots,
        bump,
    };
    if let Some(bump) = existing {
        let mut data = window_account.try_borrow_mut()?;
        *bytemuck::from_bytes_mut::<SpendWindow>(&mut data) = params(bump).value();
        return Ok(());
    }
    let bump = PdaCheck {
        program_id,
        address: window_account.address(),
        seeds: &[SpendWindow::SEED, mint.as_array()],
        mismatch: CustomRingError::InvalidSpendWindow,
    }
    .verify()?;
    let bump_seed = [bump];
    let seeds = [
        Seed::from(SpendWindow::SEED),
        Seed::from(mint.as_array().as_ref()),
        Seed::from(bump_seed.as_ref()),
    ];
    pinocchio_system::create_account_with_minimum_balance_signed(
        window_account,
        SpendWindow::SIZE,
        program_id,
        payer,
        None,
        &[Signer::from(seeds.as_ref())],
    )?;
    params(bump).init(window_account)
}
