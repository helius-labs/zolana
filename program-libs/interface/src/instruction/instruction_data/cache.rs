use solana_address::Address;
use wincode::{SchemaRead, SchemaWrite};

/// Accounts: rent payer (signer, becomes `rent_sponsor`), cache, system.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateCacheData {
    /// Immutable signer authorizing cache insertion, independent of the rent payer.
    pub write_authority: Address,
    pub nonce: u64,
    pub tree_id: u16,
    pub expires_at: i64,
}

impl CreateCacheData {
    pub fn from_bytes(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}
