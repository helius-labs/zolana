//! Loader for the key-update proposal account.
//!
//! `KeyUpdateProposal` is a variable-length wincode type, not a zero-copy
//! `bytemuck` cast, so the loader returns an owned value rather than a
//! `Ref<T>`.

use pinocchio::{error::ProgramError, AccountView};
use zolana_squads_interface::{
    error::SquadsRingError, state::key_update_proposal::KeyUpdateProposal,
};

#[inline(always)]
pub fn load_key_update_proposal(account: &AccountView) -> Result<KeyUpdateProposal, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(SquadsRingError::InvalidAccountOwner.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| SquadsRingError::InvalidKeyUpdateProposal)?;
    let value =
        KeyUpdateProposal::deserialize(&data).map_err(|_| SquadsRingError::Deserialization)?;
    if value.discriminator != KeyUpdateProposal::DISCRIMINATOR {
        return Err(SquadsRingError::InvalidDiscriminator.into());
    }
    Ok(value)
}
