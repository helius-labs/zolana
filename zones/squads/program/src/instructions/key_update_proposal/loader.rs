//! Loader for the key-update proposal account.
//!
//! `KeyUpdateProposal` is a variable-length wincode type, not a zero-copy
//! `bytemuck` cast, so the loader returns an owned value rather than a
//! `Ref<T>`.

use pinocchio::{error::ProgramError, AccountView};
use zolana_squads_interface::{
    error::SquadsZoneError, state::key_update_proposal::KeyUpdateProposal,
};

#[inline(always)]
pub fn load_key_update_proposal(account: &AccountView) -> Result<KeyUpdateProposal, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(SquadsZoneError::InvalidAccountOwner.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| SquadsZoneError::InvalidKeyUpdateProposal)?;
    let value =
        KeyUpdateProposal::deserialize(&data).map_err(|_| SquadsZoneError::Deserialization)?;
    if value.discriminator != KeyUpdateProposal::DISCRIMINATOR {
        return Err(SquadsZoneError::InvalidDiscriminator.into());
    }
    Ok(value)
}
