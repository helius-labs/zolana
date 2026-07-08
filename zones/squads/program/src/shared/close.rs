//! Account-close helper shared by every instruction that reclaims rent
//! (`close_viewing_key_account`, `cancel_proposal`, `cancel_key_update`).

use pinocchio::{AccountView, ProgramResult, Resize};
use pinocchio_system::ID as SYSTEM_PROGRAM_ID;
use zolana_squads_interface::error::SquadsZoneError;

/// Close `account`, crediting its full lamport balance to `rent_recipient`, then
/// zeroing and truncating its data and reassigning it to the system program.
///
/// `borrow_err` is the caller's account-specific error for a failed data borrow,
/// so each instruction reports its own variant. Callers must perform their own
/// access-control checks (signer, owner match, rent-recipient match) before
/// calling this.
#[inline(always)]
pub fn close_account(
    account: &mut AccountView,
    rent_recipient: &mut AccountView,
    borrow_err: SquadsZoneError,
) -> ProgramResult {
    let closed_lamports = account.lamports();
    let recipient_lamports = rent_recipient
        .lamports()
        .checked_add(closed_lamports)
        .ok_or(SquadsZoneError::ArithmeticOverflow)?;
    rent_recipient.set_lamports(recipient_lamports);
    account.set_lamports(0);

    // Zero the data then shrink to an empty account. `resize(0)` truncates the
    // data length to zero; zeroing first clears the previously occupied bytes.
    {
        let mut data = account.try_borrow_mut().map_err(|_| borrow_err)?;
        data.fill(0);
    }
    account.resize(0).map_err(|_| borrow_err)?;

    // SAFETY: the data borrow above was dropped and `resize` checked for
    // outstanding borrows, so reassigning ownership is sound.
    unsafe {
        account.assign(&SYSTEM_PROGRAM_ID);
    }
    Ok(())
}
