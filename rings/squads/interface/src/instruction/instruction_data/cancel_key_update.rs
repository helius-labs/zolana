//! `cancel_key_update` (tag 15) instruction data (spec: squads
//! `cancel_key_update`).

use wincode::{SchemaRead, SchemaWrite};

/// `cancel_key_update` instruction data (spec: squads `cancel_key_update`). The
/// spec states this instruction takes no data; the unit struct serializes to an
/// empty payload (only the dispatch tag rides the instruction).
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CancelKeyUpdateIxData;

impl CancelKeyUpdateIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
