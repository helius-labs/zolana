mod common;
mod get_encrypted_utxos_by_tags;
mod get_merkle_proofs;
mod get_non_inclusion_proofs;
mod get_shielded_transactions_by_tags;
mod types;

pub use get_encrypted_utxos_by_tags::get_encrypted_utxos_by_tags;
pub use get_merkle_proofs::get_merkle_proofs;
pub use get_non_inclusion_proofs::get_non_inclusion_proofs;
pub use get_shielded_transactions_by_tags::get_shielded_transactions_by_tags;
pub use types::{
    EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse, GetMerkleProofsRequest,
    GetMerkleProofsResponse, GetNonInclusionProofsRequest, GetNonInclusionProofsResponse,
    GetRingsByTagsRequest, GetShieldedTransactionsByTagsResponse, MerkleContext, MerkleProof,
    NonInclusionProof, RingsOutputContext, RingsOutputSlot, ShieldedTransaction,
};

#[cfg(test)]
mod tests {
    use super::common::{decode_cursor, encode_cursor, validate_proof_leaves};
    use super::get_encrypted_utxos_by_tags::EncryptedUtxoCursor;
    use super::get_shielded_transactions_by_tags::ShieldedTxCursor;
    use super::*;
    use crate::api::error::PhotonApiError;
    use crate::common::bn254::BN254_FIELD_SIZE_MINUS_ONE_BYTES;
    use crate::common::rings_tree::RingsTreeKind;
    use crate::common::typedefs::bs64_string::Base64String;
    use crate::common::typedefs::context::Context;
    use crate::common::typedefs::hash::Hash;
    use crate::common::typedefs::serializable_pubkey::SerializablePubkey;
    use crate::common::typedefs::serializable_signature::SerializableSignature;
    use serde_json::Value;
    use solana_signature::SIGNATURE_BYTES;

    #[test]
    fn cursor_codecs_round_trip_typed_values() {
        let signature = [7; SIGNATURE_BYTES];
        let encrypted = EncryptedUtxoCursor {
            slot: 42,
            signature,
            event_index: 3,
            output_index: 5,
        };
        let encrypted_cursor = Base64String(encode_cursor(&encrypted).unwrap());
        assert_eq!(
            decode_cursor::<EncryptedUtxoCursor>(&encrypted_cursor).unwrap(),
            encrypted
        );

        let shielded = ShieldedTxCursor {
            slot: 43,
            signature,
            event_index: 8,
        };
        let shielded_cursor = Base64String(encode_cursor(&shielded).unwrap());
        assert_eq!(
            decode_cursor::<ShieldedTxCursor>(&shielded_cursor).unwrap(),
            shielded
        );

        let mut malformed_cursor = shielded_cursor.0;
        malformed_cursor.push(1);
        assert!(decode_cursor::<ShieldedTxCursor>(&Base64String(malformed_cursor)).is_err());
    }

    #[test]
    fn validate_proof_leaves_rejects_out_of_field_values() {
        assert!(validate_proof_leaves(&[Hash::from(BN254_FIELD_SIZE_MINUS_ONE_BYTES)]).is_ok());

        let out_of_field = [u8::MAX; 32];
        let error = validate_proof_leaves(&[Hash::from(out_of_field)])
            .expect_err("out-of-field leaf should be rejected");

        assert!(matches!(
            error,
            PhotonApiError::ValidationError(message)
                if message.contains("outside the BN254 scalar field")
        ));
    }

    #[test]
    fn serializes_tag_api_fields_like_rings_spec() {
        let value = serde_json::to_value(EncryptedUtxoMatch {
            slot: 1,
            tx_signature: SerializableSignature::default(),
            output_slot: RingsOutputSlot {
                view_tag: Hash::new_unique(),
                output_context: RingsOutputContext {
                    hash: Hash::new_unique(),
                    tree: SerializablePubkey::new_unique(),
                    leaf_index: 2,
                },
                payload: Base64String(vec![4, 5, 6]),
            },
            tx_viewing_pk: Some(Base64String(vec![1, 2, 3])),
            salt: Some(Base64String(vec![4; 16])),
        })
        .unwrap();

        assert!(value.get("tx_signature").is_some());
        assert!(value.get("output_slot").is_some());
        assert!(value.get("tx_viewing_pk").is_some());
        assert!(value.get("salt").is_some());
        assert!(value.get("txSignature").is_none());
        assert!(value.get("outputSlot").is_none());
        assert!(value.get("txViewingPk").is_none());
        let output_slot = &value["output_slot"];
        assert!(output_slot.get("view_tag").is_some());
        assert!(output_slot.get("output_context").is_some());
        assert!(output_slot.get("payload").is_some());
        assert!(output_slot.get("proofless").is_none());
        let output_context = &output_slot["output_context"];
        assert!(output_context.get("hash").is_some());
        assert!(output_context.get("tree").is_some());
        assert!(output_context.get("leaf_index").is_some());
        assert!(output_context.get("leafIndex").is_none());

        let value = serde_json::to_value(ShieldedTransaction {
            slot: 1,
            tx_signature: SerializableSignature::default(),
            tx_viewing_pk: None,
            salt: None,
            output_slots: vec![RingsOutputSlot {
                view_tag: Hash::new_unique(),
                output_context: RingsOutputContext {
                    hash: Hash::new_unique(),
                    tree: SerializablePubkey::new_unique(),
                    leaf_index: 3,
                },
                payload: Base64String(vec![7, 8, 9]),
            }],
            nullifiers: vec![Hash::new_unique()],
            proofless: true,
        })
        .unwrap();

        assert!(value.get("tx_signature").is_some());
        assert!(value.get("tx_viewing_pk").is_some());
        assert!(value.get("output_slots").is_some());
        assert!(value.get("txSignature").is_none());
        assert!(value.get("outputSlots").is_none());

        let slot = &value["output_slots"][0];
        assert!(slot.get("view_tag").is_some());
        assert!(slot.get("output_context").is_some());
        assert!(slot.get("outputContext").is_none());
    }

    #[test]
    fn serializes_proof_api_fields_like_rings_spec() {
        let request = serde_json::to_value(GetMerkleProofsRequest {
            tree_account: SerializablePubkey::new_unique(),
            leaves: vec![Hash::new_unique()],
        })
        .unwrap();
        assert!(request.get("tree_account").is_some());
        assert!(request.get("treeAccount").is_none());

        let proof = serde_json::to_value(NonInclusionProof {
            leaf: Hash::new_unique(),
            merkle_context: MerkleContext {
                tree_type: u16::from(RingsTreeKind::Nullifier),
                tree: SerializablePubkey::new_unique(),
            },
            path: vec![Hash::new_unique()],
            low_element: Hash::new_unique(),
            low_element_index: 2,
            high_element: Hash::new_unique(),
            high_element_index: 3,
            root: Hash::new_unique(),
            root_seq: 4,
            root_index: 5,
        })
        .unwrap();

        assert!(proof.get("merkle_context").is_some());
        assert!(proof.get("low_element").is_some());
        assert!(proof.get("low_element_index").is_some());
        assert!(proof.get("high_element").is_some());
        assert!(proof.get("high_element_index").is_some());
        assert!(proof.get("root_seq").is_some());
        assert!(proof.get("root_index").is_some());
        assert!(proof.get("merkleContext").is_none());
    }

    #[test]
    fn serializes_response_cursor_like_rings_spec() {
        let value = serde_json::to_value(GetEncryptedUtxosByTagsResponse {
            context: Context { slot: 10 },
            matches: Vec::new(),
            next_cursor: Some(Base64String(vec![1, 2, 3])),
        })
        .unwrap();

        assert!(matches!(value, Value::Object(_)));
        assert!(value.get("next_cursor").is_some());
        assert!(value.get("nextCursor").is_none());
    }
}
