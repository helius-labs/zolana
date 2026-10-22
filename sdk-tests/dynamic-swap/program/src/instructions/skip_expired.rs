use light_program_profiler::profile;
use pinocchio::{
    address::address_eq,
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_account_checks::AccountIterator;

use crate::{
    error::DynamicSwapError,
    instructions::shared::close_escrow_account,
    state::{load_escrow_mut, load_pair_mut},
};

// Advances the pair's queue head past an order that can no longer settle.
// Permissionless: anyone may move the queue once its head has expired, which
// is what lets later orders settle after the maker let the head lapse.
//
// An expired open order stays open: only its refund proof can spend the order
// UTXO, and `cancel` closes it once it is behind the head. A cancellation
// marker has nothing left to refund, so this closes it and returns its rent to
// the taker.
//
// Steps:
// 1. Check that the pair, escrow, and rent recipient accounts are present and
//    writable.
// 2. Check that the instruction carries no data.
// 3. Load the pair and the escrow, verifying program ownership, exact sizes,
//    discriminators, and writable access.
// 4. Check that the escrow belongs to the pair.
// 5. Check that the escrow is the queue head.
// 6. Check that the rent recipient is the escrow's owner.
// 7. Check that the escrow is a cancellation marker or has expired.
// 8. Advance the queue head.
// 9. Close a cancellation marker to the rent recipient.
#[inline(never)]
#[profile]
pub fn process_skip_expired_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    // Step 1: Check that the accounts are present and writable.
    let pair_account = iter.next_mut("pair")?;
    let escrow_account = iter.next_mut("escrow")?;
    let rent_recipient = iter.next_mut("rent_recipient")?;
    // Step 2: Check that the instruction carries no data.
    if !data.is_empty() {
        return Err(DynamicSwapError::InvalidInstructionData.into());
    }

    // Step 3: Load the pair and the escrow.
    let pair = *load_pair_mut(pair_account)?;
    let escrow = *load_escrow_mut(escrow_account)?;
    // Step 4: Check that the escrow belongs to the pair.
    if !address_eq(&escrow.pair, pair_account.address()) {
        return Err(DynamicSwapError::PairMismatch.into());
    }
    // Step 5: Check that the escrow is the queue head.
    if escrow.order_id != pair.head_order_id {
        return Err(DynamicSwapError::NotQueueHead.into());
    }
    // Step 6: Check that the rent recipient is the escrow's owner.
    if !address_eq(&escrow.owner, rent_recipient.address()) {
        return Err(DynamicSwapError::RentRecipientMismatch.into());
    }
    // Step 7: Check that the escrow is a cancellation marker or has expired.
    // `cancel` requires expiry, so a marker has expired as well.
    let cancelled = escrow.cancelled != 0;
    if !cancelled {
        let expires_at = escrow
            .created_at
            .checked_add(pair.expiry_slots)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        if Clock::get()?.slot <= expires_at {
            return Err(DynamicSwapError::NotYetExpired.into());
        }
    }

    // Step 8: Advance the queue head.
    load_pair_mut(pair_account)?.head_order_id = escrow
        .order_id
        .checked_add(1)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    // Step 9: Close a cancellation marker to the rent recipient.
    if cancelled {
        close_escrow_account(escrow_account, rent_recipient)?;
    }
    Ok(())
}
