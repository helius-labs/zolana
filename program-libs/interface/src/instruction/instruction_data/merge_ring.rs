use wincode::{SchemaRead, SchemaWrite};

use super::merge_transact::{MergeTransactIxData, MergeTransactIxDataRef, RefConfig};
use crate::error::ShieldedPoolError;

/// `merge_ring` instruction data (spec: SPP `merge_ring`): the
/// [`MergeTransactIxData`] body plus the output `ring_data_hash` the calling
/// ring program selected. The merge proof asserts it against
/// `Output.Utxo.RingDataHash` and folds it into the public-input hash; the
/// wallet reads it from the event to reconstruct the merged ring output.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeRingIxData {
    pub output_ring_data_hash: [u8; 32],
    pub merge: MergeTransactIxData,
}

impl MergeRingIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// Zero-copy view of [`MergeRingIxData`]; the embedded [`MergeTransactIxDataRef`]
/// aliases the instruction buffer exactly as in `merge_transact`.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead)]
pub struct MergeRingIxDataRef<'a> {
    pub output_ring_data_hash: &'a [u8; 32],
    pub merge: MergeTransactIxDataRef<'a>,
}

impl<'a> MergeRingIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, ShieldedPoolError> {
        let parsed = wincode::config::deserialize(data, RefConfig::new())
            .and_then(|parsed: Self| parsed.merge.validate_shape().map(|()| parsed))
            .map_err(|_| ShieldedPoolError::InvalidMergeShape)?;
        if parsed.merge.envelope.is_some() {
            return Err(ShieldedPoolError::MergeEnvelopeUnexpected);
        }
        Ok(parsed)
    }
}
