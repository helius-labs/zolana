//! `toggle_viewing_key_account` (tag 9): flip a viewing key account between
//! active and blocked.

use pinocchio::{AccountView, ProgramResult};
use zolana_squads_interface::{
    constants::{VIEWING_KEY_STATE_ACTIVE, VIEWING_KEY_STATE_BLOCKED},
    error::SquadsZoneError,
    instruction::instruction_data::ToggleViewingKeyAccountIxData,
};

use super::loader::load_viewing_key_account;

/// `toggle_viewing_key_account` (tag 9): flip a viewing key account between
/// active and blocked.
///
/// Accounts: `[owner (signer), viewing_key_account (writable)]`.
#[inline(never)]
pub fn process_toggle_viewing_key_account_ix(
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let [owner, viewing_key_account] = accounts else {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    };

    if !owner.is_signer() {
        return Err(SquadsZoneError::MissingOwnerSignature.into());
    }

    let mut current = load_viewing_key_account(viewing_key_account)?;
    if owner.address() != &current.owner {
        return Err(SquadsZoneError::OwnerMismatch.into());
    }

    let new_state = ToggleViewingKeyAccountIxData::deserialize(data)
        .map_err(|_| SquadsZoneError::Deserialization)?
        .state;
    if new_state != VIEWING_KEY_STATE_ACTIVE && new_state != VIEWING_KEY_STATE_BLOCKED {
        return Err(SquadsZoneError::InvalidViewingKeyState.into());
    }

    // `state` lives at a fixed offset in the wincode encoding, so re-serializing
    // with the new state produces a same-length buffer that we copy back in
    // place over the account data.
    current.state = new_state;
    let bytes = current
        .serialize()
        .map_err(|_| SquadsZoneError::Deserialization)?;
    let mut account_data = viewing_key_account
        .try_borrow_mut()
        .map_err(|_| SquadsZoneError::InvalidViewingKeyAccount)?;
    let dst = account_data
        .get_mut(..bytes.len())
        .ok_or(SquadsZoneError::InvalidViewingKeyAccount)?;
    dst.copy_from_slice(&bytes);

    Ok(())
}
