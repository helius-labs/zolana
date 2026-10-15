use core::num::NonZeroU64;

use custom_ring_interface::{
    CustomRingError, FixedWindow, SetSpendWindowIxData, SpendWindow, SPEND_WINDOW,
};
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;

use crate::instructions::{
    loader::load_authorized_config,
    shared::{check_system_program, parse, upsert},
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
    } = parse(data)?;
    let window = FixedWindow {
        slots: NonZeroU64::new(window_slots).ok_or(CustomRingError::InvalidSpendWindow)?,
    };
    if deposit_cap.is_none() && withdrawal_cap.is_none() {
        return Err(CustomRingError::UncappedSpendWindow.into());
    }

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config = iter.next_account("config")?;
    let window_account = iter.next_mut("window")?;
    let system_program = iter.next_account("system_program")?;

    check_system_program(system_program)?;
    load_authorized_config(program_id, config, authority)?;
    let window_start_slot = window.start(Clock::get()?.slot).to_le_bytes();
    upsert(
        program_id,
        payer,
        window_account,
        &[SpendWindow::SEED, &mint],
        |bump| SpendWindow {
            discriminator: SPEND_WINDOW,
            mint: Address::new_from_array(mint),
            window_slots: window_slots.to_le_bytes(),
            deposit_cap: deposit_cap.map_or(0, NonZeroU64::get).to_le_bytes(),
            withdrawal_cap: withdrawal_cap.map_or(0, NonZeroU64::get).to_le_bytes(),
            window_start_slot,
            deposited: [0; 8],
            withdrawn: [0; 8],
            bump,
        },
    )
}
