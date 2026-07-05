//! `close_viewing_key_account` (tag 8): close a viewing key account and refund
//! rent to the supplied rent recipient.

use pinocchio::{AccountView, ProgramResult};
use zolana_squads_interface::error::SquadsZoneError;

use super::loader::load_viewing_key_account;
use crate::shared::close::close_account;

/// `close_viewing_key_account` (tag 8): close a viewing key account and refund
/// rent to the supplied rent recipient.
///
/// Accounts: `[owner (signer), viewing_key_account (writable), rent_recipient
/// (writable)]`.
#[inline(never)]
pub fn process_close_viewing_key_account_ix(
    accounts: &mut [AccountView],
    _data: &[u8],
) -> ProgramResult {
    let [owner, viewing_key_account, rent_recipient] = accounts else {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    };

    if !owner.is_signer() {
        return Err(SquadsZoneError::MissingOwnerSignature.into());
    }

    let current = load_viewing_key_account(viewing_key_account)?;
    if owner.address() != &current.owner {
        return Err(SquadsZoneError::OwnerMismatch.into());
    }

    // TODO(self-cpi-event): record prior account state as a self-CPI event before
    // closing (spec records the account state on close); out of scope here.

    close_account(
        viewing_key_account,
        rent_recipient,
        SquadsZoneError::InvalidViewingKeyAccount,
    )
}
