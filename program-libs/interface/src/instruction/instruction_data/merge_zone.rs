use wincode::{SchemaRead, SchemaWrite};

use super::merge_transact::{MergeTransactIxData, MergeTransactIxDataRef, RefConfig};

/// `merge_zone` instruction data (spec: SPP `merge_zone`): the
/// [`MergeTransactIxData`] body prefixed with a single-use `merge_view_tag` that
/// indexes the merged output (the owner-pubkey fetch tag of `merge_transact` does
/// not apply in a policy zone).
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeZoneIxData {
    pub merge_view_tag: [u8; 32],
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
    pub merge_view_tag: &'a [u8; 32],
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
    use crate::instruction::instruction_data::merge_transact::{
        MERGE_ENCRYPTED_UTXO_LEN, MERGE_INPUT_COUNT,
    };

    fn data() -> MergeZoneIxData {
        MergeZoneIxData {
            merge_view_tag: [9u8; 32],
            merge: MergeTransactIxData {
                expiry_unix_ts: 42,
                proof: [7u8; 192],
                output_utxo_hash: [1u8; 32],
                nullifiers: (0..MERGE_INPUT_COUNT as u8).map(|i| [i; 32]).collect(),
                utxo_tree_root_index: (0..MERGE_INPUT_COUNT as u16).collect(),
                nullifier_tree_root_index: (0..MERGE_INPUT_COUNT as u16).collect(),
                private_tx_hash: [3u8; 32],
                encrypted_utxo: (0..MERGE_ENCRYPTED_UTXO_LEN as u16)
                    .map(|i| i as u8)
                    .collect(),
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
        assert_eq!(view.merge_view_tag, &owned.merge_view_tag);
        assert_eq!(view.merge.proof, &owned.merge.proof);
        assert_eq!(view.merge.nullifiers, owned.merge.nullifiers);
        assert_eq!(
            view.merge.encrypted_utxo,
            owned.merge.encrypted_utxo.as_slice()
        );
    }

    #[test]
    fn rejects_wrong_shape() {
        let mut owned = data();
        owned.merge.nullifiers.pop();
        let bytes = owned.serialize().unwrap();
        assert!(MergeZoneIxDataRef::from_bytes(&bytes).is_err());
    }
}
