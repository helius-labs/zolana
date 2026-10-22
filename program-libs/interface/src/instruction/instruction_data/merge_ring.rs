use alloc::vec::Vec;
use wincode::{SchemaRead, SchemaWrite};

use super::merge_transact::{MergeTransactIxData, MergeTransactIxDataRef, RefConfig};
use crate::instruction::tag::RING_MERGE_TRANSACT;

/// `merge_ring` instruction data (spec: SPP `merge_ring`): the
/// [`MergeTransactIxData`] body plus the output `ring_data_hash`, the member
/// registry root and the anonymous flag the calling ring program selected. The
/// merge proof asserts the hash against `Output.Utxo.RingDataHash` and folds it
/// into the public-input hash; the wallet reads it from the event to
/// reconstruct the merged ring output. The ring merge proof binds
/// `merge.output_encryption` too.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeRingIxData {
    pub output_ring_data_hash: [u8; 32],
    /// The proof opens the owner's escrowed key under this root.
    pub member_registry_root: [u8; 32],
    /// Set from the signing ring's mode, the proof skips the escrow relation under it.
    pub anonymous: bool,
    pub merge: MergeTransactIxData,
}

/// The [`MergeRingIxData`] fields a ring program writes before the merge body it forwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeRingPrefix<'a> {
    pub output_ring_data_hash: &'a [u8; 32],
    pub member_registry_root: &'a [u8; 32],
    pub anonymous: bool,
}

impl MergeRingPrefix<'_> {
    pub const LEN: usize = 32 + 32 + 1;

    /// The tagged SPP instruction data, `merge` a serialized [`MergeTransactIxData`].
    pub fn instruction_data(self, merge: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(1 + Self::LEN + merge.len());
        data.push(RING_MERGE_TRANSACT);
        data.extend_from_slice(self.output_ring_data_hash);
        data.extend_from_slice(self.member_registry_root);
        data.push(u8::from(self.anonymous));
        data.extend_from_slice(merge);
        data
    }
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
    pub member_registry_root: &'a [u8; 32],
    pub anonymous: bool,
    pub merge: MergeTransactIxDataRef<'a>,
}

impl<'a> MergeRingIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, wincode::ReadError> {
        let parsed: Self = wincode::config::deserialize_exact(data, RefConfig::new())?;
        parsed.merge.validate_shape()?;
        Ok(parsed)
    }
}
