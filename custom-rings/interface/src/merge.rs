use wincode::{SchemaRead, SchemaWrite};
use zolana_interface::instruction::instruction_data::merge_transact::{
    MergeTransactIxData, MergeTransactIxDataRef,
};

/// Compact ring-program merge request. The ring program replaces the root
/// history index with the authenticated root before forwarding to SPP.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CustomRingMergeIxData {
    pub registry_root_index: u8,
    pub output_ring_data_hash: [u8; 32],
    pub merge: MergeTransactIxData,
}

impl CustomRingMergeIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// Borrowed view of the compact request. The merge body and proof alias the
/// instruction buffer, including the variable-length nullifier list.
pub struct CustomRingMergeIxDataRef<'a> {
    pub registry_root_index: u8,
    pub output_ring_data_hash: &'a [u8; 32],
    pub merge: MergeTransactIxDataRef<'a>,
    /// Exact serialized SPP merge body, reused when forwarding the instruction.
    pub merge_body: &'a [u8],
}

impl<'a> CustomRingMergeIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, wincode::ReadError> {
        let (registry_root_index, body) = data
            .split_first()
            .ok_or(wincode::ReadError::Custom("missing root index"))?;
        let (output_ring_data_hash, body) = body
            .split_first_chunk::<32>()
            .ok_or(wincode::ReadError::Custom("missing ring data hash"))?;
        Ok(Self {
            registry_root_index: *registry_root_index,
            output_ring_data_hash,
            merge: MergeTransactIxDataRef::from_bytes(body)?,
            merge_body: body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_interface::instruction::instruction_data::merge_transact::MergeProof;

    #[test]
    fn compact_request_round_trips_and_rejects_trailing_bytes() {
        let request = CustomRingMergeIxData {
            registry_root_index: 3,
            output_ring_data_hash: [8; 32],
            merge: MergeTransactIxData {
                expiry_unix_ts: 42,
                proof: MergeProof::zeroed(),
                output_utxo_hash: [1; 32],
                output_ciphertext_salt: [2; 16],
                output_ciphertext: [[3; 32]; 3],
                private_tx_hash: [4; 32],
                nullifiers: vec![[5; 32]],
                utxo_tree_root_index: 0,
                nullifier_tree_root_index: 0,
                cache_slot: None,
            },
        };
        let mut bytes = request.serialize().unwrap();
        assert_eq!(CustomRingMergeIxData::deserialize(&bytes).unwrap(), request);
        let view = CustomRingMergeIxDataRef::from_bytes(&bytes).unwrap();
        assert_eq!(view.registry_root_index, 3);
        assert_eq!(view.output_ring_data_hash, &[8; 32]);
        assert_eq!(view.merge.nullifiers, request.merge.nullifiers);
        bytes.push(0);
        assert!(CustomRingMergeIxDataRef::from_bytes(&bytes).is_err());
    }
}
