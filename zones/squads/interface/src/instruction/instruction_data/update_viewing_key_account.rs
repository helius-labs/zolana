//! `update_viewing_key_account` (tag 6) instruction data (spec: squads
//! `update_viewing_key_account`).

use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use crate::{state::key_update_proposal::KeyOperation, types::Address};

/// `update_viewing_key_account` instruction data (spec: squads
/// `update_viewing_key_account`). Creates a key update proposal carrying the
/// recovery-key operations (or a single auditor update), the executor that
/// fills and settles it, and the proposal expiry. The proposal PDA is
/// domain-separated by `domain`.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct UpdateViewingKeyAccountIxData {
    /// Domain separation for the proposal PDA.
    pub domain: u16,
    /// Signer allowed to fill the buffer and settle the update.
    pub executor: Address,
    /// Recovery-key changes applied in order, or a single auditor update.
    #[wincode(with = "containers::Vec<KeyOperation, FixIntLen<u8>>")]
    pub operations: Vec<KeyOperation>,
    /// Unix timestamp after which execution fails.
    pub expiry: i64,
}

impl UpdateViewingKeyAccountIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
