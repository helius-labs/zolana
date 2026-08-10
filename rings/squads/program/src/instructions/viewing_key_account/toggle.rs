use pinocchio::{AccountView, ProgramResult};
use zolana_squads_interface::{
    constants::{VIEWING_KEY_STATE_ACTIVE, VIEWING_KEY_STATE_BLOCKED},
    error::SquadsRingError,
    instruction::instruction_data::ToggleViewingKeyAccountIxData,
};

use super::loader::load_viewing_key_account;
use crate::instructions::ring_config::loader::load_ring_config;
use crate::shared::owner::is_owner_identity;

/// `toggle_viewing_key_account` (tag 9): flip a viewing key account between
/// active and blocked.
///
/// Accounts: `[authority (signer), viewing_key_account (writable), ring_config
/// (readonly)]`.
///
/// The authority is the account's own owner or the ring co-signer. A keypair
/// owner is stored as a hash of its address and can never satisfy the owner
/// test, so without the co-signer such an account could never be blocked.
#[inline(never)]
pub fn process_toggle_viewing_key_account_ix(
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let [authority, viewing_key_account, ring_config] = accounts else {
        return Err(SquadsRingError::InvalidInstructionData.into());
    };

    if !authority.is_signer() {
        return Err(SquadsRingError::MissingOwnerSignature.into());
    }

    let mut current = load_viewing_key_account(viewing_key_account)?;
    let ring = load_ring_config(ring_config)?;
    if authority.address() != &ring.co_signer
        && !is_owner_identity(authority, current.owner.to_bytes())?
    {
        return Err(SquadsRingError::OwnerMismatch.into());
    }

    let new_state = ToggleViewingKeyAccountIxData::deserialize(data)
        .map_err(|_| SquadsRingError::Deserialization)?
        .state;
    if new_state != VIEWING_KEY_STATE_ACTIVE && new_state != VIEWING_KEY_STATE_BLOCKED {
        return Err(SquadsRingError::InvalidViewingKeyState.into());
    }

    // Changing `state` does not change the wincode length, so the copy overwrites
    // the account data completely.
    current.state = new_state;
    let bytes = current
        .serialize()
        .map_err(|_| SquadsRingError::Serialization)?;
    let mut account_data = viewing_key_account
        .try_borrow_mut()
        .map_err(|_| SquadsRingError::InvalidViewingKeyAccount)?;
    let dst = account_data
        .get_mut(..bytes.len())
        .ok_or(SquadsRingError::InvalidViewingKeyAccount)?;
    dst.copy_from_slice(&bytes);

    Ok(())
}
