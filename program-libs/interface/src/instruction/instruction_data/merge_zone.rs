use wincode::{SchemaRead, SchemaWrite};

use super::merge_transact::{MergeTransactIxData, MergeTransactIxDataRef, RefConfig};

/// `merge_zone` instruction data (spec: SPP `merge_zone`): the
/// [`MergeTransactIxData`] body plus the output `zone_data_hash` the calling
/// zone program selected. The merge proof asserts it against
/// `Output.Utxo.ZoneDataHash` and folds it into the public-input hash; the
/// wallet reads it from the event to reconstruct the merged zone output.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeZoneIxData {
    pub output_zone_data_hash: [u8; 32],
    pub merge: MergeTransactIxData,
}

impl MergeZoneIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// Zero-copy view of [`MergeZoneIxData`]; the embedded [`MergeTransactIxDataRef`]
/// aliases the instruction buffer exactly as in `merge_transact`.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead)]
pub struct MergeZoneIxDataRef<'a> {
    pub output_zone_data_hash: &'a [u8; 32],
    pub merge: MergeTransactIxDataRef<'a>,
}

impl<'a> MergeZoneIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, wincode::ReadError> {
        let parsed: Self = wincode::config::deserialize(data, RefConfig::new())?;
        parsed.merge.validate_shape()?;
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::instruction_data::merge_transact::{MergeProof, MERGE_INPUT_COUNT};

    fn data() -> MergeZoneIxData {
        MergeZoneIxData {
            output_zone_data_hash: [8u8; 32],
            merge: MergeTransactIxData {
                expiry_unix_ts: 42,
                proof: MergeProof {
                    a: [1u8; 32],
                    b: [2u8; 64],
                    c: [3u8; 32],
                },
                output_utxo_hash: [1u8; 32],
                nullifiers: (0..MERGE_INPUT_COUNT as u8).map(|i| [i; 32]).collect(),
                utxo_tree_root_index: (0..MERGE_INPUT_COUNT as u16).collect(),
                nullifier_tree_root_index: (10..10 + MERGE_INPUT_COUNT as u16).collect(),
                private_tx_hash: [3u8; 32],
                eddsa_owner: false,
            },
        }
    }

    #[test]
    fn round_trips_owned_and_ref() {
        let owned = data();
        let bytes = owned.serialize().unwrap();
        assert_eq!(MergeZoneIxData::deserialize(&bytes).unwrap(), owned);

        let view = MergeZoneIxDataRef::from_bytes(&bytes).unwrap();
        assert_eq!(view.output_zone_data_hash, &owned.output_zone_data_hash);
        assert_eq!(view.merge.proof.a, &owned.merge.proof.a);
        assert_eq!(view.merge.nullifiers, owned.merge.nullifiers);
    }

    #[test]
    fn rejects_wrong_shape() {
        let mut owned = data();
        owned.merge.nullifiers.pop();
        let bytes = owned.serialize().unwrap();
        assert!(MergeZoneIxDataRef::from_bytes(&bytes).is_err());
    }
}
