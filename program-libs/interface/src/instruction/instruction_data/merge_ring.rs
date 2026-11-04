use alloc::vec::Vec;
use wincode::{SchemaRead, SchemaWrite};

use super::merge_transact::{MergeTransactIxData, MergeTransactIxDataRef, RefConfig};

/// `merge_ring` instruction data (spec: SPP `merge_ring`): the
/// [`MergeTransactIxData`] body plus the output `ring_data_hash` the calling
/// ring program selected. The merge proof asserts it against
/// `Output.Utxo.RingDataHash` and folds it into the public-input hash; the
/// wallet reads it from the event to reconstruct the merged ring output. The
/// ring merge proof does not bind `merge.output_encryption`: SPP publishes it
/// unverified, and a ring that needs it recoverable enforces it in its own
/// program.
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
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, wincode::ReadError> {
        let parsed: Self = wincode::config::deserialize(data, RefConfig::new())?;
        parsed.merge.validate_shape()?;
        Ok(parsed)
    }
}

/// Who authorizes a `merge_ring_v2`, beyond the ring's `ring_config` signature.
/// A proof under the other authority fails verification: the zero-key circuit
/// publishes its owner and the nonzero-key circuit publishes zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u8")]
pub enum MergeRingAuthority {
    /// A nonzero nullifier key.
    #[wincode(tag = 0)]
    Ring,
    /// The zero nullifier key: an account signs and its hashed key is published.
    #[wincode(tag = 1)]
    OwnerSigned,
}

/// `merge_ring_v2` instruction data, a [`MergeRingIxData`] that also names its
/// authority. The proof binds `merge.output_encryption`.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeRingV2IxData {
    pub output_ring_data_hash: [u8; 32],
    pub authority: MergeRingAuthority,
    pub merge: MergeTransactIxData,
}

impl MergeRingV2IxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// Zero-copy view of [`MergeRingV2IxData`].
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead)]
pub struct MergeRingV2IxDataRef<'a> {
    pub output_ring_data_hash: &'a [u8; 32],
    pub authority: MergeRingAuthority,
    pub merge: MergeTransactIxDataRef<'a>,
}

impl<'a> MergeRingV2IxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, wincode::ReadError> {
        let parsed: Self = wincode::config::deserialize(data, RefConfig::new())?;
        parsed.merge.validate_shape()?;
        Ok(parsed)
    }
}
