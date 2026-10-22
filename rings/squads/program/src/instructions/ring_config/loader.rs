//! Loader for the singleton ring config account.
//!
//! Checks program ownership, borrows the account data, deserializes the owned
//! wincode struct, and rejects a mismatched discriminator. `RingConfig` is a
//! variable-length wincode type (not a zero-copy `bytemuck` cast), so the loader
//! returns an owned value rather than a `Ref<T>`.
//!
//! Mirrors the SPP loader pattern (owner check, deserialize, discriminator
//! check), adapted for owned wincode deserialization: a deserialize failure maps
//! to [`SquadsRingError::Deserialization`], a discriminator mismatch to
//! [`SquadsRingError::InvalidDiscriminator`], and a foreign owner to
//! [`SquadsRingError::InvalidAccountOwner`].

use pinocchio::{error::ProgramError, AccountView};
use zolana_squads_interface::{error::SquadsRingError, state::ring_config::RingConfig};

#[inline(always)]
pub fn load_ring_config(account: &AccountView) -> Result<RingConfig, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(SquadsRingError::InvalidAccountOwner.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| SquadsRingError::InvalidRingConfig)?;
    let value = RingConfig::deserialize(&data).map_err(|_| SquadsRingError::Deserialization)?;
    if value.discriminator != RingConfig::DISCRIMINATOR {
        return Err(SquadsRingError::InvalidDiscriminator.into());
    }
    Ok(value)
}
