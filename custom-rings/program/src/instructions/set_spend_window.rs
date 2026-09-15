use core::num::NonZeroU64;

use custom_ring_interface::{FixedWindow, SetSpendWindowIxData, SpendWindow};
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_authorized_config, load_spend_window_mut},
        shared::PdaCreate,
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
    let window = FixedWindow {
        slots: NonZeroU64::new(window_slots).ok_or(CustomRingError::InvalidSpendWindow)?,
    };

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
    let window_start_slot = window.start(Clock::get()?.slot);
    let params = |bump| SpendWindowInitParams {
        mint,
        window_slots,
        deposit_cap,
        withdrawal_cap,
        window_start_slot,
        bump,
    };
    if let Some(mut existing) = load_spend_window_mut(program_id, window_account, &mint)? {
        *existing = params(existing.bump).value();
        return Ok(());
    }
    let bump = PdaCreate {
        program_id,
        payer,
        seeds: &[SpendWindow::SEED, mint.as_array()],
        mismatch: CustomRingError::InvalidSpendWindow,
    }
    .create::<SpendWindow>(window_account)?;
    params(bump).init(window_account)
}
