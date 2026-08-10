//! `fill_key_update` (tag 7) instruction data (spec: squads `fill_key_update`).

use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use crate::types::SharedKeyCiphertext;

/// `fill_key_update` instruction data (spec: squads `fill_key_update`). The
/// executor appends a chunk of new shared-key ciphertexts to the key update
/// proposal buffer (in chunks if the full set exceeds one transaction).
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct FillKeyUpdateIxData {
    /// Ciphertexts to append.
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub ciphertexts: Vec<SharedKeyCiphertext>,
}

impl FillKeyUpdateIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
