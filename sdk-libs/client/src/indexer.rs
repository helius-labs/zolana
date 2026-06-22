//! Blocking RPC adapter for the Zolana indexer API.

use solana_address::Address;
use solana_signature::Signature;
use zolana_api::{
    types::{Base64String, Hash as ApiHash, SerializablePubkey, ZolanaOutputSlot as ApiOutputSlot},
    BlockingZolanaApi,
};
use zolana_keypair::{constants::P256_PUBKEY_LEN, P256Pubkey};

use crate::{
    error::ClientError,
    rpc::{
        Context, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse, GetMerkleProofsResponse,
        GetNonInclusionProofsResponse, GetShieldedTransactionsByTagsResponse, MerkleContext,
        MerkleProof, NonInclusionProof, OutputSlot, Rpc, ShieldedTransaction,
    },
};

#[derive(Clone, Debug)]
pub struct ZolanaIndexer {
    api: BlockingZolanaApi,
}

impl ZolanaIndexer {
    pub fn new(url: impl AsRef<str>) -> Self {
        Self {
            api: BlockingZolanaApi::new(url),
        }
    }

    pub fn with_api(api: BlockingZolanaApi) -> Self {
        Self { api }
    }

    pub fn with_http_trace(mut self) -> Self {
        self.api = self.api.with_http_trace();
        self
    }

    pub fn api(&self) -> &BlockingZolanaApi {
        &self.api
    }
}

impl Rpc for ZolanaIndexer {
    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        let response = self
            .api
            .get_encrypted_utxos_by_tags(
                tags.into_iter().map(encode_hash).collect(),
                encode_cursor(cursor),
                limit.map(u64::from),
            )
            .map_err(indexer_error)?;

        Ok(GetEncryptedUtxosByTagsResponse {
            context: convert_context(response.context),
            matches: response
                .matches
                .into_iter()
                .enumerate()
                .map(|(index, item)| convert_encrypted_utxo_match(index, item))
                .collect::<Result<Vec<_>, _>>()?,
            next_cursor: decode_optional_cursor(response.next_cursor)?,
        })
    }

    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        let response = self
            .api
            .get_shielded_transactions_by_tags(
                tags.into_iter().map(encode_hash).collect(),
                encode_cursor(cursor),
                limit.map(u64::from),
            )
            .map_err(indexer_error)?;

        Ok(GetShieldedTransactionsByTagsResponse {
            context: convert_context(response.context),
            transactions: response
                .transactions
                .into_iter()
                .enumerate()
                .map(|(index, item)| convert_shielded_transaction(index, item))
                .collect::<Result<Vec<_>, _>>()?,
            next_cursor: decode_optional_cursor(response.next_cursor)?,
        })
    }

    fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        let response = self
            .api
            .get_merkle_proofs(
                encode_pubkey(tree_account),
                leaves.into_iter().map(encode_hash).collect(),
            )
            .map_err(indexer_error)?;

        Ok(GetMerkleProofsResponse {
            context: convert_context(response.context),
            proofs: response
                .proofs
                .into_iter()
                .enumerate()
                .map(|(index, proof)| convert_merkle_proof(index, proof))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        let response = self
            .api
            .get_non_inclusion_proofs(
                encode_pubkey(tree_account),
                leaves.into_iter().map(encode_hash).collect(),
            )
            .map_err(indexer_error)?;

        Ok(GetNonInclusionProofsResponse {
            context: convert_context(response.context),
            proofs: response
                .proofs
                .into_iter()
                .enumerate()
                .map(|(index, proof)| convert_non_inclusion_proof(index, proof))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

fn indexer_error(error: zolana_api::ApiError) -> ClientError {
    ClientError::Rpc(format!("indexer API: {error}"))
}

fn convert_context(context: zolana_api::Context) -> Context {
    Context { slot: context.slot }
}

fn convert_encrypted_utxo_match(
    index: usize,
    item: zolana_api::EncryptedUtxoMatch,
) -> Result<EncryptedUtxoMatch, ClientError> {
    Ok(EncryptedUtxoMatch {
        slot: item.slot,
        tx_signature: decode_signature(
            &item.tx_signature,
            &format!("matches[{index}].tx_signature"),
        )?,
        view_tag: decode_hash(&item.view_tag, &format!("matches[{index}].view_tag"))?,
        utxo_hash: decode_hash(&item.utxo_hash, &format!("matches[{index}].utxo_hash"))?,
        output_tree: decode_pubkey(&item.output_tree, &format!("matches[{index}].output_tree"))?,
        leaf_index: item.leaf_index,
        tx_viewing_pk: decode_optional_p256(
            item.tx_viewing_pk,
            &format!("matches[{index}].tx_viewing_pk"),
        )?,
        salt: decode_optional_salt(item.salt, &format!("matches[{index}].salt"))?,
        ciphertext: decode_base64(&item.ciphertext, &format!("matches[{index}].ciphertext"))?,
    })
}

fn convert_shielded_transaction(
    index: usize,
    item: zolana_api::ShieldedTransaction,
) -> Result<ShieldedTransaction, ClientError> {
    Ok(ShieldedTransaction {
        slot: item.slot,
        tx_signature: decode_signature(
            &item.tx_signature,
            &format!("transactions[{index}].tx_signature"),
        )?,
        tx_viewing_pk: decode_optional_p256(
            item.tx_viewing_pk,
            &format!("transactions[{index}].tx_viewing_pk"),
        )?,
        salt: decode_optional_salt(item.salt, &format!("transactions[{index}].salt"))?,
        output_slots: item
            .output_slots
            .into_iter()
            .enumerate()
            .map(|(slot_index, slot)| {
                convert_output_slot(
                    slot,
                    &format!("transactions[{index}].output_slots[{slot_index}]"),
                )
            })
            .collect::<Result<Vec<_>, _>>()?,
        nullifiers: item
            .nullifiers
            .iter()
            .enumerate()
            .map(|(nullifier_index, nullifier)| {
                decode_hash(
                    nullifier,
                    &format!("transactions[{index}].nullifiers[{nullifier_index}]"),
                )
            })
            .collect::<Result<Vec<_>, _>>()?,
        proofless: item.proofless,
    })
}

fn convert_output_slot(slot: ApiOutputSlot, field: &str) -> Result<OutputSlot, ClientError> {
    Ok(OutputSlot {
        view_tag: decode_hash(&slot.view_tag, &format!("{field}.view_tag"))?,
        hash: decode_hash(&slot.hash, &format!("{field}.hash"))?,
        payload: decode_base64(&slot.payload, &format!("{field}.payload"))?,
    })
}

fn convert_merkle_proof(
    index: usize,
    proof: zolana_api::MerkleProof,
) -> Result<MerkleProof, ClientError> {
    Ok(MerkleProof {
        leaf: decode_hash(&proof.leaf, &format!("proofs[{index}].leaf"))?,
        merkle_context: convert_merkle_context(
            proof.merkle_context,
            &format!("proofs[{index}].merkle_context"),
        )?,
        path: proof
            .path
            .iter()
            .enumerate()
            .map(|(path_index, hash)| {
                decode_hash(hash, &format!("proofs[{index}].path[{path_index}]"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        leaf_index: proof.leaf_index,
        root: decode_hash(&proof.root, &format!("proofs[{index}].root"))?,
        root_seq: proof.root_seq,
        root_index: proof.root_index,
    })
}

fn convert_non_inclusion_proof(
    index: usize,
    proof: zolana_api::NonInclusionProof,
) -> Result<NonInclusionProof, ClientError> {
    Ok(NonInclusionProof {
        leaf: decode_hash(&proof.leaf, &format!("proofs[{index}].leaf"))?,
        merkle_context: convert_merkle_context(
            proof.merkle_context,
            &format!("proofs[{index}].merkle_context"),
        )?,
        path: proof
            .path
            .iter()
            .enumerate()
            .map(|(path_index, hash)| {
                decode_hash(hash, &format!("proofs[{index}].path[{path_index}]"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        low_element: decode_hash(&proof.low_element, &format!("proofs[{index}].low_element"))?,
        low_element_index: proof.low_element_index,
        high_element: decode_hash(
            &proof.high_element,
            &format!("proofs[{index}].high_element"),
        )?,
        high_element_index: proof.high_element_index,
        root: decode_hash(&proof.root, &format!("proofs[{index}].root"))?,
        root_seq: proof.root_seq,
        root_index: proof.root_index,
    })
}

fn convert_merkle_context(
    context: zolana_api::MerkleContext,
    field: &str,
) -> Result<MerkleContext, ClientError> {
    Ok(MerkleContext {
        tree_type: context.tree_type,
        tree: decode_pubkey(&context.tree, &format!("{field}.tree"))?,
    })
}

fn encode_hash(hash: [u8; 32]) -> ApiHash {
    ApiHash(bs58::encode(hash).into_string())
}

fn encode_pubkey(address: Address) -> SerializablePubkey {
    SerializablePubkey(bs58::encode(address.to_bytes()).into_string())
}

fn encode_cursor(cursor: Option<Vec<u8>>) -> Option<Base64String> {
    cursor.map(|cursor| Base64String(base64::encode(cursor)))
}

fn decode_optional_cursor(cursor: Option<Base64String>) -> Result<Option<Vec<u8>>, ClientError> {
    cursor
        .map(|cursor| decode_base64(&cursor, "next_cursor"))
        .transpose()
}

fn decode_signature(
    signature: &zolana_api::SerializableSignature,
    field: &str,
) -> Result<Signature, ClientError> {
    signature
        .0
        .parse::<Signature>()
        .map_err(|error| decode_error(field, error))
}

fn decode_pubkey(
    pubkey: &zolana_api::SerializablePubkey,
    field: &str,
) -> Result<Address, ClientError> {
    Ok(Address::new_from_array(decode_base58_32(&pubkey.0, field)?))
}

fn decode_hash(hash: &ApiHash, field: &str) -> Result<[u8; 32], ClientError> {
    decode_base58_32(&hash.0, field)
}

fn decode_base58_32(value: &str, field: &str) -> Result<[u8; 32], ClientError> {
    let bytes = bs58::decode(value)
        .into_vec()
        .map_err(|error| decode_error(field, error))?;
    fixed_bytes(bytes, 32, field)
}

fn decode_base64(value: &Base64String, field: &str) -> Result<Vec<u8>, ClientError> {
    base64::decode(&value.0).map_err(|error| decode_error(field, error))
}

fn decode_optional_p256(
    value: Option<Base64String>,
    field: &str,
) -> Result<Option<P256Pubkey>, ClientError> {
    value
        .map(|value| {
            let bytes = fixed_bytes(decode_base64(&value, field)?, P256_PUBKEY_LEN, field)?;
            P256Pubkey::from_bytes(bytes).map_err(|error| decode_error(field, error))
        })
        .transpose()
}

fn decode_optional_salt(
    value: Option<Base64String>,
    field: &str,
) -> Result<Option<[u8; 16]>, ClientError> {
    value
        .map(|value| fixed_bytes(decode_base64(&value, field)?, 16, field))
        .transpose()
}

fn fixed_bytes<const N: usize>(
    bytes: Vec<u8>,
    expected_len: usize,
    field: &str,
) -> Result<[u8; N], ClientError> {
    let actual_len = bytes.len();
    bytes.try_into().map_err(|_| {
        ClientError::Rpc(format!(
            "invalid indexer field {field}: expected {expected_len} bytes, got {actual_len}"
        ))
    })
}

fn decode_error(field: &str, error: impl std::fmt::Display) -> ClientError {
    ClientError::Rpc(format!("invalid indexer field {field}: {error}"))
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::mpsc,
        thread,
        time::Duration,
    };

    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;
    use serde_json::{json, Value};

    use super::*;

    #[test]
    fn round_trips_hashes_and_cursors() {
        let hash = [7u8; 32];
        let encoded = encode_hash(hash);
        assert_eq!(decode_hash(&encoded, "hash").unwrap(), hash);

        let cursor = Some(vec![1, 2, 3, 4]);
        let encoded = encode_cursor(cursor.clone());
        assert_eq!(decode_optional_cursor(encoded).unwrap(), cursor);
    }

    #[test]
    fn decodes_compressed_p256_pubkey() {
        let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let public = secret.public_key();
        let point = public.to_encoded_point(true);
        let key = decode_optional_p256(
            Some(Base64String(base64::encode(point.as_bytes()))),
            "tx_viewing_pk",
        )
        .unwrap()
        .unwrap();

        assert_eq!(key.as_bytes(), point.as_bytes());
    }

    #[test]
    fn rejects_bad_hash_length() {
        let err = decode_hash(&ApiHash(bs58::encode([1u8; 31]).into_string()), "root")
            .expect_err("short hash must fail");
        assert!(err.to_string().contains("expected 32 bytes"));
    }

    #[test]
    fn get_encrypted_utxos_by_tags_encodes_request_and_decodes_matches() {
        let tag_a = bytes32(1);
        let tag_b = bytes32(2);
        let utxo_hash = bytes32(4);
        let output_tree = Address::new_from_array(bytes32(5));
        let signature = signature(9);
        let (tx_viewing_pk_bytes, tx_viewing_pk) = compressed_p256_pubkey(3);
        let response = rpc_result(json!({
            "context": { "slot": 42 },
            "matches": [{
                "slot": 7,
                "tx_signature": signature.to_string(),
                "view_tag": encode_hash_string(tag_a),
                "utxo_hash": encode_hash_string(utxo_hash),
                "output_tree": encode_pubkey_string(output_tree),
                "leaf_index": 11,
                "tx_viewing_pk": base64::encode(&tx_viewing_pk_bytes),
                "ciphertext": base64::encode([8, 9, 10]),
            }],
            "next_cursor": base64::encode([5, 6]),
        }));
        let server = MockServer::respond_once(response);
        let indexer = ZolanaIndexer::new(server.url());

        let got = indexer
            .get_encrypted_utxos_by_tags(vec![tag_a, tag_b], Some(vec![1, 2, 3]), Some(7))
            .expect("encrypted UTXO lookup");
        let request = server.request();

        assert_eq!(request.path, "/get_encrypted_utxos_by_tags");
        assert_json_rpc_request(&request.body, "get_encrypted_utxos_by_tags");
        assert_eq!(
            request.body["params"],
            json!({
                "tags": [encode_hash_string(tag_a), encode_hash_string(tag_b)],
                "cursor": base64::encode([1, 2, 3]),
                "limit": 7,
            })
        );
        assert_eq!(got.context.slot, 42);
        assert_eq!(got.next_cursor, Some(vec![5, 6]));
        assert_eq!(got.matches.len(), 1);
        assert_eq!(got.matches[0].slot, 7);
        assert_eq!(got.matches[0].tx_signature, signature);
        assert_eq!(got.matches[0].view_tag, tag_a);
        assert_eq!(got.matches[0].utxo_hash, utxo_hash);
        assert_eq!(got.matches[0].output_tree, output_tree);
        assert_eq!(got.matches[0].leaf_index, 11);
        assert_eq!(got.matches[0].tx_viewing_pk, Some(tx_viewing_pk));
        assert_eq!(got.matches[0].ciphertext, vec![8, 9, 10]);
    }

    #[test]
    fn get_shielded_transactions_by_tags_maps_output_hashes_and_nullifiers() {
        let tag = bytes32(11);
        let output_hash = bytes32(12);
        let nullifier = bytes32(13);
        let signature = signature(14);
        let response = rpc_result(json!({
            "context": { "slot": 51 },
            "transactions": [{
                "slot": 50,
                "tx_signature": signature.to_string(),
                "tx_viewing_pk": null,
                "output_slots": [{
                    "view_tag": encode_hash_string(tag),
                    "hash": encode_hash_string(output_hash),
                    "payload": base64::encode([21, 22]),
                }],
                "nullifiers": [encode_hash_string(nullifier)],
                "proofless": true,
            }],
            "next_cursor": base64::encode([23]),
        }));
        let server = MockServer::respond_once(response);
        let indexer = ZolanaIndexer::new(server.url());

        let got = indexer
            .get_shielded_transactions_by_tags(vec![tag], None, Some(1))
            .expect("shielded transaction lookup");
        let request = server.request();

        assert_eq!(request.path, "/get_shielded_transactions_by_tags");
        assert_json_rpc_request(&request.body, "get_shielded_transactions_by_tags");
        assert_eq!(
            request.body["params"],
            json!({
                "tags": [encode_hash_string(tag)],
                "limit": 1,
            })
        );
        assert_eq!(got.context.slot, 51);
        assert_eq!(got.next_cursor, Some(vec![23]));
        assert_eq!(got.transactions.len(), 1);
        let tx = &got.transactions[0];
        assert_eq!(tx.slot, 50);
        assert_eq!(tx.tx_signature, signature);
        assert_eq!(tx.tx_viewing_pk, None);
        assert!(tx.proofless);
        assert_eq!(tx.nullifiers, vec![nullifier]);
        assert_eq!(tx.output_slots.len(), 1);
        assert_eq!(tx.output_slots[0].view_tag, tag);
        assert_eq!(tx.output_slots[0].hash, output_hash);
        assert_eq!(tx.output_slots[0].payload, vec![21, 22]);
    }

    #[test]
    fn get_merkle_proofs_encodes_tree_and_maps_root_metadata() {
        let tree = Address::new_from_array(bytes32(31));
        let leaf_a = bytes32(32);
        let leaf_b = bytes32(33);
        let path = vec![bytes32(34), bytes32(35)];
        let root = bytes32(36);
        let response = rpc_result(json!({
            "context": { "slot": 80 },
            "proofs": [{
                "leaf": encode_hash_string(leaf_a),
                "merkle_context": {
                    "tree_type": 1,
                    "tree": encode_pubkey_string(tree),
                },
                "path": path.iter().copied().map(encode_hash_string).collect::<Vec<_>>(),
                "leaf_index": 9,
                "root": encode_hash_string(root),
                "root_seq": 10,
                "root_index": 11,
            }],
        }));
        let server = MockServer::respond_once(response);
        let indexer = ZolanaIndexer::new(server.url());

        let got = indexer
            .get_merkle_proofs(tree, vec![leaf_a, leaf_b])
            .expect("merkle proofs");
        let request = server.request();

        assert_eq!(request.path, "/get_merkle_proofs");
        assert_json_rpc_request(&request.body, "get_merkle_proofs");
        assert_eq!(
            request.body["params"],
            json!({
                "tree_account": encode_pubkey_string(tree),
                "leaves": [encode_hash_string(leaf_a), encode_hash_string(leaf_b)],
            })
        );
        assert_eq!(got.context.slot, 80);
        assert_eq!(got.proofs.len(), 1);
        assert_eq!(got.proofs[0].leaf, leaf_a);
        assert_eq!(got.proofs[0].merkle_context.tree_type, 1);
        assert_eq!(got.proofs[0].merkle_context.tree, tree);
        assert_eq!(got.proofs[0].path, path);
        assert_eq!(got.proofs[0].leaf_index, 9);
        assert_eq!(got.proofs[0].root, root);
        assert_eq!(got.proofs[0].root_seq, 10);
        assert_eq!(got.proofs[0].root_index, 11);
    }

    #[test]
    fn get_non_inclusion_proofs_maps_adjacency_witness() {
        let tree = Address::new_from_array(bytes32(41));
        let leaf = bytes32(42);
        let low = bytes32(43);
        let high = bytes32(44);
        let path = vec![bytes32(45), bytes32(46)];
        let root = bytes32(47);
        let response = rpc_result(json!({
            "context": { "slot": 90 },
            "proofs": [{
                "leaf": encode_hash_string(leaf),
                "merkle_context": {
                    "tree_type": 2,
                    "tree": encode_pubkey_string(tree),
                },
                "path": path.iter().copied().map(encode_hash_string).collect::<Vec<_>>(),
                "low_element": encode_hash_string(low),
                "low_element_index": 3,
                "high_element": encode_hash_string(high),
                "high_element_index": 4,
                "root": encode_hash_string(root),
                "root_seq": 12,
                "root_index": 13,
            }],
        }));
        let server = MockServer::respond_once(response);
        let indexer = ZolanaIndexer::new(server.url());

        let got = indexer
            .get_non_inclusion_proofs(tree, vec![leaf])
            .expect("non-inclusion proofs");
        let request = server.request();

        assert_eq!(request.path, "/get_non_inclusion_proofs");
        assert_json_rpc_request(&request.body, "get_non_inclusion_proofs");
        assert_eq!(
            request.body["params"],
            json!({
                "tree_account": encode_pubkey_string(tree),
                "leaves": [encode_hash_string(leaf)],
            })
        );
        assert_eq!(got.context.slot, 90);
        assert_eq!(got.proofs.len(), 1);
        assert_eq!(got.proofs[0].leaf, leaf);
        assert_eq!(got.proofs[0].merkle_context.tree_type, 2);
        assert_eq!(got.proofs[0].merkle_context.tree, tree);
        assert_eq!(got.proofs[0].path, path);
        assert_eq!(got.proofs[0].low_element, low);
        assert_eq!(got.proofs[0].low_element_index, 3);
        assert_eq!(got.proofs[0].high_element, high);
        assert_eq!(got.proofs[0].high_element_index, 4);
        assert_eq!(got.proofs[0].root, root);
        assert_eq!(got.proofs[0].root_seq, 12);
        assert_eq!(got.proofs[0].root_index, 13);
    }

    #[test]
    fn wraps_json_rpc_errors() {
        let response = json!({
            "id": "test-account",
            "jsonrpc": "2.0",
            "error": {
                "code": -32602,
                "message": "bad tag",
            },
        });
        let server = MockServer::respond_once(response);
        let indexer = ZolanaIndexer::new(server.url());

        let err = indexer
            .get_encrypted_utxos_by_tags(vec![bytes32(1)], None, None)
            .expect_err("JSON-RPC errors must surface");
        let _ = server.request();

        assert!(err.to_string().contains("indexer API"));
        assert!(err.to_string().contains("bad tag"));
    }

    #[test]
    fn rejects_malformed_output_slot_hash() {
        let tag = bytes32(51);
        let response = rpc_result(json!({
            "context": { "slot": 1 },
            "transactions": [{
                "slot": 1,
                "tx_signature": signature(52).to_string(),
                "tx_viewing_pk": null,
                "output_slots": [{
                    "view_tag": encode_hash_string(tag),
                    "hash": bs58::encode([1u8; 31]).into_string(),
                    "payload": base64::encode([1]),
                }],
                "nullifiers": [],
                "proofless": true,
            }],
            "next_cursor": null,
        }));
        let server = MockServer::respond_once(response);
        let indexer = ZolanaIndexer::new(server.url());

        let err = indexer
            .get_shielded_transactions_by_tags(vec![tag], None, None)
            .expect_err("short output hash must fail");
        let _ = server.request();

        assert!(err
            .to_string()
            .contains("transactions[0].output_slots[0].hash"));
        assert!(err.to_string().contains("expected 32 bytes"));
    }

    fn assert_json_rpc_request(body: &Value, method: &str) {
        assert_eq!(body["id"], "test-account");
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["method"], method);
    }

    fn rpc_result(result: Value) -> Value {
        json!({
            "id": "test-account",
            "jsonrpc": "2.0",
            "result": result,
        })
    }

    fn bytes32(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn signature(value: u8) -> Signature {
        Signature::from([value; 64])
    }

    fn encode_hash_string(hash: [u8; 32]) -> String {
        bs58::encode(hash).into_string()
    }

    fn encode_pubkey_string(pubkey: Address) -> String {
        bs58::encode(pubkey.to_bytes()).into_string()
    }

    fn compressed_p256_pubkey(seed: u8) -> (Vec<u8>, P256Pubkey) {
        let secret = SecretKey::from_slice(&[seed; 32]).unwrap();
        let public = secret.public_key();
        let point = public.to_encoded_point(true);
        let bytes = point.as_bytes().to_vec();
        let key_bytes: [u8; P256_PUBKEY_LEN] = bytes.clone().try_into().unwrap();
        let key = P256Pubkey::from_bytes(key_bytes).unwrap();
        (bytes, key)
    }

    struct RecordedRequest {
        path: String,
        body: Value,
    }

    struct MockServer {
        url: String,
        request_rx: mpsc::Receiver<RecordedRequest>,
        handle: thread::JoinHandle<()>,
    }

    impl MockServer {
        fn respond_once(response: Value) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let (request_tx, request_rx) = mpsc::channel();
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_http_request(&mut stream);
                request_tx.send(request).unwrap();
                write_http_response(&mut stream, response);
            });
            Self {
                url,
                request_rx,
                handle,
            }
        }

        fn url(&self) -> &str {
            &self.url
        }

        fn request(self) -> RecordedRequest {
            let request = self
                .request_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("mock server did not receive a request");
            self.handle.join().unwrap();
            request
        }
    }

    fn read_http_request(stream: &mut TcpStream) -> RecordedRequest {
        let mut data = Vec::new();
        let mut buf = [0_u8; 1024];
        let mut body_start = None;
        let mut content_len = None;
        loop {
            let read = stream.read(&mut buf).unwrap();
            assert!(read != 0, "HTTP client closed before sending a request");
            data.extend_from_slice(&buf[..read]);
            if body_start.is_none() {
                if let Some(index) = data.windows(4).position(|window| window == b"\r\n\r\n") {
                    body_start = Some(index + 4);
                    let header = String::from_utf8_lossy(&data[..index]);
                    content_len = parse_content_length(&header);
                }
            }
            if let (Some(start), Some(len)) = (body_start, content_len) {
                if data.len() >= start + len {
                    break;
                }
            }
        }

        let body_start = body_start.expect("request has headers");
        let header = String::from_utf8_lossy(&data[..body_start]);
        let path = header
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .expect("request line has a path")
            .to_string();
        let body = serde_json::from_slice(&data[body_start..]).expect("request body is JSON");
        RecordedRequest { path, body }
    }

    fn parse_content_length(header: &str) -> Option<usize> {
        header.lines().find_map(|line| {
            let lower = line.to_ascii_lowercase();
            lower
                .strip_prefix("content-length:")
                .map(str::trim)
                .map(|value| value.parse().unwrap())
        })
    }

    fn write_http_response(stream: &mut TcpStream, body: Value) {
        let body = serde_json::to_string(&body).unwrap();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
    }
}
