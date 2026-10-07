use wincode::{SchemaRead, SchemaWrite};

use super::merge_transact::{parse_merge_view, MergeBody, MergeBodyRef};
use crate::error::ShieldedPoolError;

/// `merge_ring` instruction data (spec: SPP `merge_ring`): the shared
/// [`MergeBody`] plus the output `ring_data_hash` the calling ring program
/// selected. The merge proof asserts it against `Output.Utxo.RingDataHash` and
/// folds it into the public-input hash; the wallet reads it from the event to
/// reconstruct the merged ring output. The ring circuit has no proof commitment
/// and no encrypted envelope, so the encoding has no field for either.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeRingIxData {
    pub output_ring_data_hash: [u8; 32],
    pub body: MergeBody,
}

impl MergeRingIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// Zero-copy view of [`MergeRingIxData`].
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead)]
pub struct MergeRingIxDataRef<'a> {
    pub output_ring_data_hash: &'a [u8; 32],
    pub body: MergeBodyRef<'a>,
}

impl<'a> MergeRingIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, ShieldedPoolError> {
        parse_merge_view(data, |ix: &Self| &ix.body)
    }
}
