//! `close_viewing_key_account` (tag 8) instruction data (spec: squads
//! `close_viewing_key_account`).

use wincode::{SchemaRead, SchemaWrite};

/// `close_viewing_key_account` instruction data (spec: squads
/// `close_viewing_key_account`). The spec states this instruction takes no data;
/// the unit struct serializes to an empty payload (only the dispatch tag rides
/// the instruction). Kept as a struct for naming/round-trip consistency with the
/// other instruction-data types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CloseViewingKeyAccountIxData;

impl CloseViewingKeyAccountIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
