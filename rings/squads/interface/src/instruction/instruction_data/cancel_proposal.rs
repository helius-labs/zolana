//! `cancel_proposal` (tag 12) instruction data (spec: squads `cancel_proposal`).

use wincode::{SchemaRead, SchemaWrite};

/// `cancel_proposal` instruction data (spec: squads `cancel_proposal`). The spec
/// states this instruction takes no data; the unit struct serializes to an empty
/// payload (only the dispatch tag rides the instruction).
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CancelProposalIxData;

impl CancelProposalIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
