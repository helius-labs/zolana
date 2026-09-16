use wincode::{SchemaRead, SchemaWrite};

/// Accounts: rent payer (signer), registry owner or ring config (signer), cache, system.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateCacheData {
    pub owner_kind: u8,
    pub operation_id: [u8; 32],
    pub tree_id: u16,
    pub close_authority: [u8; 32],
}

impl CreateCacheData {
    pub fn from_bytes(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}
