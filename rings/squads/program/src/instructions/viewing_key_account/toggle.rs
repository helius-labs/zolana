use pinocchio::{AccountView, ProgramResult};
use zolana_squads_interface::{
    constants::{VIEWING_KEY_STATE_ACTIVE, VIEWING_KEY_STATE_BLOCKED},
    error::SquadsZoneError,
    instruction::instruction_data::ToggleViewingKeyAccountIxData,
};

use super::loader::load_viewing_key_account;
use crate::instructions::zone_config::loader::load_zone_config;
use crate::shared::owner::is_owner_identity;

/// `toggle_viewing_key_account` (tag 9): flip a viewing key account between
/// active and blocked.
///
/// Accounts: `[authority (signer), viewing_key_account (writable), zone_config
/// (readonly)]`.
///
/// The authority is the account's own owner or the zone co-signer. A keypair
/// owner is stored as a hash of its address and can never satisfy the owner
/// test, so without the co-signer such an account could never be blocked.
#[inline(never)]
pub fn process_toggle_viewing_key_account_ix(
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let [authority, viewing_key_account, zone_config] = accounts else {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    };

    if !authority.is_signer() {
        return Err(SquadsZoneError::MissingOwnerSignature.into());
    }

    let mut current = load_viewing_key_account(viewing_key_account)?;
    let zone = load_zone_config(zone_config)?;
    if authority.address() != &zone.co_signer
        && !is_owner_identity(authority, current.owner.to_bytes())?
    {
        return Err(SquadsZoneError::OwnerMismatch.into());
    }

    let new_state = ToggleViewingKeyAccountIxData::deserialize(data)
        .map_err(|_| SquadsZoneError::Deserialization)?
        .state;
    if new_state != VIEWING_KEY_STATE_ACTIVE && new_state != VIEWING_KEY_STATE_BLOCKED {
        return Err(SquadsZoneError::InvalidViewingKeyState.into());
    }

    // Changing `state` does not change the wincode length, so the copy overwrites
    // the account data completely.
    current.state = new_state;
    let bytes = current
        .serialize()
        .map_err(|_| SquadsZoneError::Serialization)?;
    let mut account_data = viewing_key_account
        .try_borrow_mut()
        .map_err(|_| SquadsZoneError::InvalidViewingKeyAccount)?;
    let dst = account_data
        .get_mut(..bytes.len())
        .ok_or(SquadsZoneError::InvalidViewingKeyAccount)?;
    dst.copy_from_slice(&bytes);

    Ok(())
}
