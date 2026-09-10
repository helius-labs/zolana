use solana_address::Address;
use thiserror::Error;
use zolana_hasher::primitives::hash_bytes;

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
    /// Matches SPP's owner proof input derivation, one list serves sender and
    /// recipient rules.
    pub fn owner_tag(tag: &[u8; 32]) -> Result<Self, MemberError> {
        Self::from_hash_bytes(tag)
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
        assert_eq!(member.as_bytes(), &hash_bytes(&tag).unwrap());
    }

    #[test]
    fn asset_shares_the_owner_tag_derivation() {
        let address = Address::new_from_array([9u8; 32]);
        assert_eq!(
            Member::asset(&address).unwrap(),
            Member::owner_tag(&[9u8; 32]).unwrap()
        );
    }
}
