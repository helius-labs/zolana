//! `merge_transact` (tag 2) instruction data (spec: squads `merge_transact`).

use wincode::{SchemaRead, SchemaWrite};
use zolana_interface::instruction::instruction_data::merge_ring::MergeRingIxData;

/// `merge_transact` instruction data (spec: squads `merge_transact`).
///
/// A merge authority consolidates one owner's ring UTXOs into a single output of
/// the same owner and total value. The SPP `merge_ring` payload is forwarded
/// unchanged; the ring only authorizes the caller.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeTransactIxData {
    pub spp: MergeRingIxData,
}

impl MergeTransactIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
