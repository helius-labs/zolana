use solana_address::Address;
use thiserror::Error;
use zolana_hasher::primitives::hash_bytes;

/// Zero is the circuit slot padding value, never a member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyMember([u8; 32]);

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum PolicyMemberError {
    #[error("hashing failed")]
    Hashing,
    #[error("member derives to zero")]
    Zero,
}

impl PolicyMember {
    /// Matches SPP's owner proof input derivation, one list serves sender and
    /// recipient rules.
    pub fn owner_tag(tag: &[u8; 32]) -> Result<Self, PolicyMemberError> {
        Self::from_hash_bytes(tag)
    }

    /// The mint, encoded exactly as the `Asset` field of the UTXO hash.
    pub fn asset(mint: &Address) -> Result<Self, PolicyMemberError> {
        Self::from_hash_bytes(mint.as_array())
    }

    pub fn ring(program_id: &Address) -> Result<Self, PolicyMemberError> {
        Self::from_hash_bytes(program_id.as_array())
    }

    pub fn destination(address: &Address) -> Result<Self, PolicyMemberError> {
        Self::from_hash_bytes(address.as_array())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Only the zero pad is rejected, a non-canonical value fails its own
    /// membership proof closed.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PolicyMemberError> {
        if bytes == [0u8; 32] {
            return Err(PolicyMemberError::Zero);
        }
        Ok(Self(bytes))
    }

    fn from_hash_bytes(bytes: &[u8; 32]) -> Result<Self, PolicyMemberError> {
        let field = hash_bytes(bytes).map_err(|_| PolicyMemberError::Hashing)?;
        if field == [0u8; 32] {
            return Err(PolicyMemberError::Zero);
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
        let member = PolicyMember::owner_tag(&tag).unwrap();
        assert_eq!(member.as_bytes(), &hash_bytes(&tag).unwrap());
    }

    #[test]
    fn asset_ring_and_destination_share_the_owner_tag_derivation() {
        let address = Address::new_from_array([9u8; 32]);
        let expected = PolicyMember::owner_tag(&[9u8; 32]).unwrap();
        assert_eq!(PolicyMember::asset(&address).unwrap(), expected);
        assert_eq!(PolicyMember::ring(&address).unwrap(), expected);
        assert_eq!(PolicyMember::destination(&address).unwrap(), expected);
    }
}
