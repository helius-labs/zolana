use alloc::vec::Vec;
use wincode::{SchemaRead, SchemaWrite};

use super::merge_transact::{MergeTransactIxData, MergeTransactIxDataRef, RefConfig};

/// `merge_ring` instruction data (spec: SPP `merge_ring`): the
/// [`MergeTransactIxData`] body plus the output `ring_data_hash` and an
/// authenticated member-registry root selected by the calling ring program.
/// The merge proof asserts the hash against `Output.Utxo.RingDataHash` and
/// proves owner-key escrow under that root; both enter the public-input hash. The
/// wallet reads it from the event to reconstruct the merged ring output.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeRingIxData {
    pub output_ring_data_hash: [u8; 32],
    /// Recent member-registry root proving that the owner nullifier key was
    /// registered with an auditor-recoverable escrow ciphertext.
    pub member_registry_root: [u8; 32],
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
    pub member_registry_root: &'a [u8; 32],
    pub merge: MergeTransactIxDataRef<'a>,
}

impl<'a> MergeRingIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, wincode::ReadError> {
        let parsed: Self = wincode::config::deserialize_exact(data, RefConfig::new())?;
        parsed.merge.validate_shape()?;
        Ok(parsed)
    }
}
