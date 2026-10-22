//! Loader for the key-update proposal account.
//!
//! Checks program ownership, borrows the account data, deserializes the owned
//! wincode struct, and rejects a mismatched discriminator. `KeyUpdateProposal`
//! is a variable-length wincode type (not a zero-copy `bytemuck` cast), so the
//! loader returns an owned value rather than a `Ref<T>`.
//!
//! Mirrors the SPP loader pattern (owner check, deserialize, discriminator
//! check), adapted for owned wincode deserialization: a deserialize failure maps
//! to [`SquadsRingError::Deserialization`], a discriminator mismatch to
//! [`SquadsRingError::InvalidDiscriminator`], and a foreign owner to
//! [`SquadsRingError::InvalidAccountOwner`].

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
