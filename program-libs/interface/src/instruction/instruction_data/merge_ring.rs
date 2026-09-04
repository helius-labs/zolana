use wincode::{SchemaRead, SchemaWrite};

use super::{
    borrowed::{finish, read},
    merge_transact::{MergeTransactIxData, MergeTransactIxDataRef},
};

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeRingIxDataRef<'a> {
    pub output_ring_data_hash: &'a [u8; 32],
    pub merge: MergeTransactIxDataRef<'a>,
}

impl<'a> MergeRingIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, wincode::ReadError> {
        // Exact: trailing bytes after a merge payload are unbound by any proof
        // input, so they must be rejected rather than ignored.
        let mut cursor = data;
        let parsed = Self {
            output_ring_data_hash: read::<&[u8; 32]>(&mut cursor)?,
            merge: MergeTransactIxDataRef::read_from(&mut cursor)?,
        };
        finish(cursor)?;
        parsed.merge.validate_shape()?;
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::instruction_data::merge_transact::{
        MergeProof, MERGE_DEFAULT_INPUT_COUNT,
    };

    fn data() -> MergeRingIxData {
        MergeRingIxData {
            output_ring_data_hash: [8u8; 32],
            merge: MergeTransactIxData {
                expiry_unix_ts: 42,
                proof: MergeProof {
                    a: [1u8; 32],
                    b: [2u8; 64],
                    c: [3u8; 32],
                },
                output_utxo_hash: [1u8; 32],
                nullifiers: (0..MERGE_DEFAULT_INPUT_COUNT as u8)
                    .map(|i| [i; 32])
                    .collect(),
                utxo_tree_root_index: (0..MERGE_DEFAULT_INPUT_COUNT as u16).collect(),
                nullifier_tree_root_index: (10..10 + MERGE_DEFAULT_INPUT_COUNT as u16).collect(),
                private_tx_hash: [3u8; 32],
                eddsa_owner: false,
            },
        }
    }

    #[test]
    fn round_trips_owned_and_ref() {
        let owned = data();
        let bytes = owned.serialize().unwrap();
        assert_eq!(MergeRingIxData::deserialize(&bytes).unwrap(), owned);

        let view = MergeRingIxDataRef::from_bytes(&bytes).unwrap();
        assert_eq!(view.output_ring_data_hash, &owned.output_ring_data_hash);
        assert_eq!(view.merge.proof.a, &owned.merge.proof.a);
        assert_eq!(view.merge.nullifiers.len(), owned.merge.nullifiers.len());
        for (got, want) in view
            .merge
            .nullifiers
            .try_iter()
            .zip(&owned.merge.nullifiers)
        {
            assert_eq!(got.unwrap(), want);
        }
    }

    #[test]
    fn rejects_wrong_shape() {
        let mut owned = data();
        owned.merge.nullifiers.pop();
        let bytes = owned.serialize().unwrap();
        assert!(MergeRingIxDataRef::from_bytes(&bytes).is_err());
    }
}
