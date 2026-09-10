use solana_address::Address;
use thiserror::Error;
use zolana_hasher::primitives::{hash_bytes, solana_owner_identity};

/// A list subject, the field element the transfer openings carry for it, never zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member([u8; 32]);

/// A tag fails to derive a usable member.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum MemberError {
    #[error("hashing failed")]
    Hashing,
    #[error("member derives to zero")]
    Zero,
}

impl Member {
    /// The tagged identity SPP derives for a Solana owner.
    pub fn owner_tag(tag: &[u8; 32]) -> Result<Self, MemberError> {
        let identity = solana_owner_identity(tag).map_err(|_| MemberError::Hashing)?;
        Self::from_bytes(identity)
    }

    /// An owner identity SPP derived for any curve.
    pub fn owner_identity(identity: &[u8; 32]) -> Result<Self, MemberError> {
        Self::from_bytes(*identity)
    }

    /// The mint, encoded exactly as the `Asset` field of the UTXO hash.
    pub fn asset(mint: &Address) -> Result<Self, MemberError> {
        Self::from_hash_bytes(mint.as_array())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Only the zero pad is rejected, a non-canonical value fails its own
    /// membership proof closed.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, MemberError> {
        if bytes == [0u8; 32] {
            return Err(MemberError::Zero);
        }
        Ok(Self(bytes))
    }

    fn from_hash_bytes(bytes: &[u8; 32]) -> Result<Self, MemberError> {
        let field = hash_bytes(bytes).map_err(|_| MemberError::Hashing)?;
        if field == [0u8; 32] {
            return Err(MemberError::Zero);
        }
        Ok(Self(field))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_matches_the_owner_proof_input_derivation() {
        let tag = [7u8; 32];
        let member = Member::owner_tag(&tag).unwrap();
        assert_eq!(member.as_bytes(), &solana_owner_identity(&tag).unwrap());
        assert_eq!(Member::owner_identity(member.as_bytes()).unwrap(), member);
    }

    #[test]
    fn an_asset_and_an_owner_with_equal_bytes_are_different_members() {
        let address = Address::new_from_array([9u8; 32]);
        assert_eq!(
            Member::asset(&address).unwrap().as_bytes(),
            &hash_bytes(&[9u8; 32]).unwrap()
        );
        assert_ne!(
            Member::asset(&address).unwrap(),
            Member::owner_tag(&[9u8; 32]).unwrap()
        );
    }
}
