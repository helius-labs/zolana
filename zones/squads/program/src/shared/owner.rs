//! Canonical viewing-key-account owner authentication.

use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_squads_interface::error::SquadsZoneError;

/// Verify that `owner` controls the identity stored in a viewing key account.
///
/// The stored identity is the canonical `hash_bytes(address)` shared with the
/// proof and SDK paths. A raw address is not accepted as a second encoding.
#[inline(always)]
pub fn verify_owner_identity(owner: &AccountView, expected_owner: [u8; 32]) -> ProgramResult {
    if is_owner_identity(owner, expected_owner)? {
        return Ok(());
    }
    Err(SquadsZoneError::OwnerMismatch.into())
}

/// The same test as [`verify_owner_identity`] for a path that accepts a second
/// authority, so the caller can report which authority it wanted.
#[inline(always)]
pub fn is_owner_identity(
    owner: &AccountView,
    expected_owner: [u8; 32],
) -> Result<bool, ProgramError> {
    owner_identity_matches(owner.address().to_bytes(), expected_owner)
}

#[inline(always)]
fn owner_identity_matches(
    owner_address: [u8; 32],
    expected_owner: [u8; 32],
) -> Result<bool, ProgramError> {
    let owner_field = zolana_hasher::primitives::hash_bytes(&owner_address)
        .map_err(|_| SquadsZoneError::ProofHashingFailed)?;
    Ok(owner_field == expected_owner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_canonical_field_owner_encoding() {
        let owner_address = [0x2au8; 32];
        let owner_field =
            zolana_hasher::primitives::hash_bytes(&owner_address).expect("hash owner address");

        assert!(!owner_identity_matches(owner_address, owner_address).expect("raw owner"));
        assert!(owner_identity_matches(owner_address, owner_field).expect("field owner"));
        assert!(!owner_identity_matches(owner_address, [0x55; 32]).expect("wrong owner"));
    }
}
