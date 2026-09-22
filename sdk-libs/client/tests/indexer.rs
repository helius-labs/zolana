use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    thread,
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use serde_json::{json, Value};

use solana_address::Address;
use solana_signature::Signature;
use zolana_client::{
    indexer::ZolanaIndexer,
    rpc::{
        Context, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse, GetMerkleProofsResponse,
        GetNonInclusionProofsResponse, GetShieldedTransactionsByNullifiersResponse,
        GetShieldedTransactionsByTagsResponse, MerkleContext, MerkleProof, NonInclusionProof,
        OutputContext, OutputSlot, Rpc, ShieldedTransaction,
    },
    ClientError,
};
use zolana_keypair::{constants::P256_PUBKEY_LEN, P256Pubkey};

#[test]
fn decodes_compressed_p256_pubkey() {
    let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let public = secret.public_key();
    let point = public.to_encoded_point(true);
    let response = rpc_result(json!({
        "context": { "blockTime": 1, "slot": 1 },
        "transactions": [{
            "eventIndex": 0,
            "transaction": {
                "slot": 1,
                "txSignature": signature(1).to_string(),
                "txViewingPk": STANDARD.encode(point.as_bytes()),
                "outputSlots": [],
                "messages": [],
                "nullifiers": [],
                "proofless": false,
            },
        }],
    }));
    let server = MockServer::respond_once(response);
    let result = ZolanaIndexer::new(server.url())
        .get_shielded_transactions_by_signature(signature(1), None)
        .expect("decode transaction viewing key");
    let _ = server.request();
    let key = result
        .transactions
        .first()
        .unwrap()
        .transaction
        .tx_viewing_pk
        .unwrap();

    assert_eq!(key.as_bytes(), point.as_bytes());
}

#[test]
fn get_encrypted_utxos_by_tags_encodes_request_and_decodes_matches() {
    let tag_a = bytes32(1);
    let tag_b = bytes32(2);
    let utxo_hash = bytes32(4);
    let output_tree_id = 5u16;
    let signature = signature(9);
    let (tx_viewing_pk_bytes, tx_viewing_pk) = compressed_p256_pubkey(3);
    let response = rpc_result(json!({
        "context": { "blockTime": 42, "slot": 1 },
        "outputTreeId": 6,
        "matches": [{
            "slot": 7,
            "txSignature": signature.to_string(),
            "outputSlot": {
                "viewTag": encode_hash_string(tag_a),
                "outputContext": {
                    "hash": encode_hash_string(utxo_hash),
                    "tree": encode_pubkey_string(zolana_interface::pda::tree(output_tree_id)),
                    "treeId": output_tree_id,
                    "leafIndex": 11,
                },
                "payload": STANDARD.encode([8, 9, 10]),
            },
            "txViewingPk": STANDARD.encode(&tx_viewing_pk_bytes),
        }],
        "nextCursor": STANDARD.encode([5, 6]),
    }));
    let server = MockServer::respond_once(response);
    let indexer = ZolanaIndexer::new(server.url());

    let got = indexer
        .get_encrypted_utxos_by_tags(vec![tag_a, tag_b], Some(vec![1, 2, 3]), Some(7), None)
        .expect("encrypted UTXO lookup");
    let request = server.request();

    assert_eq!(request.path, "/getEncryptedUtxosByTags");
    assert_json_rpc_request(&request.body, "getEncryptedUtxosByTags");
    assert_eq!(
        request.body["params"],
        json!({
            "tags": [encode_hash_string(tag_a), encode_hash_string(tag_b)],
            "cursor": STANDARD.encode([1, 2, 3]),
            "limit": 7,
        })
    );
    assert_eq!(
        got,
        GetEncryptedUtxosByTagsResponse {
            context: Context {
                block_time: 42,
                slot: 1
            },
            output_tree_id: Some(6),
            matches: vec![EncryptedUtxoMatch {
                slot: 7,
                tx_signature: signature,
                output_slot: OutputSlot {
                    view_tag: tag_a,
                    output_context: OutputContext {
                        hash: utxo_hash,
                        tree_id: output_tree_id,
                        leaf_index: 11,
                    },
                    payload: vec![8, 9, 10],
                },
                tx_viewing_pk: Some(tx_viewing_pk),
                salt: None,
            }],
            next_cursor: Some(vec![5, 6]),
            scanned_through: None,
        }
    );
}

#[test]
fn get_shielded_transactions_by_tags_maps_output_hashes_and_nullifiers() {
    let tag = bytes32(11);
    let output_hash = bytes32(12);
    let output_tree_id = 15u16;
    let nullifier = bytes32(13);
    let signature = signature(14);
    let response = rpc_result(json!({
        "context": { "blockTime": 51, "slot": 1 },
        "outputTreeId": 2,
        "transactions": [{
            "slot": 50,
            "txSignature": signature.to_string(),
            "txViewingPk": null,
            "outputSlots": [{
                "viewTag": encode_hash_string(tag),
                "outputContext": {
                    "hash": encode_hash_string(output_hash),
                    "tree": encode_pubkey_string(zolana_interface::pda::tree(output_tree_id)),
                    "treeId": output_tree_id,
                    "leafIndex": 16,
                },
                "payload": STANDARD.encode([21, 22]),
            }],
            "messages": [],
            "nullifiers": [encode_hash_string(nullifier)],
            "proofless": true,
        }],
        "nextCursor": STANDARD.encode([23]),
    }));
    let server = MockServer::respond_once(response);
    let indexer = ZolanaIndexer::new(server.url());

    let got = indexer
        .get_shielded_transactions_by_tags(vec![tag], None, Some(1), None)
        .expect("shielded transaction lookup");
    let request = server.request();

    assert_eq!(request.path, "/getShieldedTransactionsByTags");
    assert_json_rpc_request(&request.body, "getShieldedTransactionsByTags");
    assert_eq!(
        request.body["params"],
        json!({
            "tags": [encode_hash_string(tag)],
            "limit": 1,
        })
    );
    assert_eq!(
        got,
        GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 51,
                slot: 1
            },
            output_tree_id: Some(2),
            transactions: vec![ShieldedTransaction {
                slot: 50,
                tx_signature: signature,
                event_index: None,
                tx_viewing_pk: None,
                salt: None,
                output_slots: vec![OutputSlot {
                    view_tag: tag,
                    output_context: OutputContext {
                        hash: output_hash,
                        tree_id: output_tree_id,
                        leaf_index: 16,
                    },
                    payload: vec![21, 22],
                }],
                nullifiers: vec![nullifier],
                proofless: true,
                messages: vec![],
                ring_config: None,
                ring_program_id: None,
            }],
            next_cursor: Some(vec![23]),
            scanned_through: None,
        }
    );
}

#[test]
fn get_shielded_transactions_by_signature_preserves_event_index() {
    let signature = signature(24);
    let response = rpc_result(json!({
        "context": { "blockTime": 52, "slot": 1 },
        "transactions": [{
            "eventIndex": 3,
            "transaction": {
                "slot": 50,
                "txSignature": signature.to_string(),
                "txViewingPk": null,
                "outputSlots": [],
                "messages": [],
                "nullifiers": [],
                "proofless": false,
            },
        }],
    }));
    let server = MockServer::respond_once(response);
    let indexer = ZolanaIndexer::new(server.url());

    let got = indexer
        .get_shielded_transactions_by_signature(signature, None)
        .expect("direct shielded transaction lookup");
    let request = server.request();

    assert_eq!(request.path, "/getShieldedTransactionsBySignature");
    assert_json_rpc_request(&request.body, "getShieldedTransactionsBySignature");
    assert_eq!(
        request.body["params"],
        json!({ "txSignature": signature.to_string() })
    );
    let indexed = got
        .transactions
        .first()
        .expect("one indexed Rings event for the signature");
    assert_eq!(got.transactions.len(), 1);
    assert_eq!(indexed.event_index, 3);
    assert_eq!(indexed.transaction.tx_signature, signature);
}

#[test]
fn get_shielded_transactions_by_nullifiers_uses_dedicated_rpc() {
    let nullifier_a = bytes32(24);
    let nullifier_b = bytes32(25);
    let response = rpc_result(json!({
        "context": { "blockTime": 52, "slot": 1 },
        "transactions": [],
        "nextCursor": null,
    }));
    let server = MockServer::respond_once(response);
    let indexer = ZolanaIndexer::new(server.url());

    let got = indexer
        .get_shielded_transactions_by_nullifiers(
            vec![nullifier_a, nullifier_b],
            Some(vec![1, 2]),
            Some(3),
            None,
        )
        .expect("nullifier transaction lookup");
    let request = server.request();

    assert_eq!(request.path, "/getShieldedTransactionsByNullifiers");
    assert_json_rpc_request(&request.body, "getShieldedTransactionsByNullifiers");
    assert_eq!(
        request.body["params"],
        json!({
            "nullifiers": [
                encode_hash_string(nullifier_a),
                encode_hash_string(nullifier_b)
            ],
            "cursor": STANDARD.encode([1, 2]),
            "limit": 3,
        })
    );
    assert_eq!(
        got,
        GetShieldedTransactionsByNullifiersResponse {
            context: Context {
                block_time: 52,
                slot: 1
            },
            // An indexer that has not synced tree metadata omits the
            // field rather than naming a tree it cannot vouch for.
            output_tree_id: None,
            transactions: vec![],
            next_cursor: None,
            scanned_through: None,
        }
    );
}

#[test]
fn get_merkle_proofs_encodes_tree_and_maps_root_metadata() {
    let tree = Address::new_from_array(bytes32(31));
    let leaf_a = bytes32(32);
    let path = vec![bytes32(34), bytes32(35)];
    let root = bytes32(36);
    let response = rpc_result(json!({
        "context": { "blockTime": 80, "slot": 1 },
        "proofs": [{
            "leaf": encode_hash_string(leaf_a),
            "merkleContext": {
                "treeType": 1,
                "tree": encode_pubkey_string(tree),
            },
            "path": path.iter().copied().map(encode_hash_string).collect::<Vec<_>>(),
            "leafIndex": 9,
            "root": encode_hash_string(root),
            "rootSeq": 10,
            "rootIndex": 11,
        }],
    }));
    let server = MockServer::respond_once(response);
    let indexer = ZolanaIndexer::new(server.url());

    let got = indexer
        .get_merkle_proofs(tree, vec![leaf_a], None)
        .expect("merkle proofs");
    let request = server.request();

    assert_eq!(request.path, "/getMerkleProofs");
    assert_json_rpc_request(&request.body, "getMerkleProofs");
    assert_eq!(
        request.body["params"],
        json!({
            "treeAccount": encode_pubkey_string(tree),
            "leaves": [encode_hash_string(leaf_a)],
        })
    );
    assert_eq!(
        got,
        GetMerkleProofsResponse {
            context: Context {
                block_time: 80,
                slot: 1
            },
            proofs: vec![MerkleProof {
                leaf: leaf_a,
                merkle_context: MerkleContext { tree_type: 1, tree },
                path,
                leaf_index: 9,
                root,
                root_seq: 10,
                root_index: 11,
            }],
        }
    );
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
        "context": { "blockTime": 90, "slot": 1 },
        "proofs": [{
            "leaf": encode_hash_string(leaf),
            "merkleContext": {
                "treeType": 2,
                "tree": encode_pubkey_string(tree),
            },
            "path": path.iter().copied().map(encode_hash_string).collect::<Vec<_>>(),
            "lowElement": encode_hash_string(low),
            "lowElementIndex": 3,
            "highElement": encode_hash_string(high),
            "highElementIndex": 4,
            "root": encode_hash_string(root),
            "rootSeq": 12,
            "rootIndex": 13,
        }],
    }));
    let server = MockServer::respond_once(response);
    let indexer = ZolanaIndexer::new(server.url());

    let got = indexer
        .get_non_inclusion_proofs(tree, vec![leaf], None)
        .expect("non-inclusion proofs");
    let request = server.request();

    assert_eq!(request.path, "/getNonInclusionProofs");
    assert_json_rpc_request(&request.body, "getNonInclusionProofs");
    assert_eq!(
        request.body["params"],
        json!({
            "treeAccount": encode_pubkey_string(tree),
            "leaves": [encode_hash_string(leaf)],
        })
    );
    assert_eq!(
        got,
        GetNonInclusionProofsResponse {
            context: Context {
                block_time: 90,
                slot: 1
            },
            proofs: vec![NonInclusionProof {
                leaf,
                merkle_context: MerkleContext { tree_type: 2, tree },
                path,
                low_element: low,
                low_element_index: 3,
                high_element: high,
                high_element_index: 4,
                root,
                root_seq: 12,
                root_index: 13,
            }],
        }
    );
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
        .get_encrypted_utxos_by_tags(vec![bytes32(1)], None, None, None)
        .expect_err("JSON-RPC errors must surface");
    let _ = server.request();

    assert!(matches!(&err, ClientError::Indexer(_)));
    assert!(err.to_string().contains("bad tag"));
}

#[test]
fn classifies_transient_indexer_errors_for_retry() {
    let server = MockServer::respond_with_status("429 Too Many Requests", json!("retry later"));
    let indexer = ZolanaIndexer::new(server.url());
    let rate_limit = indexer
        .get_shielded_transactions_by_signature(signature(1), None)
        .expect_err("rate limit must surface");
    let _ = server.request();
    assert!(matches!(rate_limit, ClientError::IndexerUnavailable(_)));
    assert!(indexer.should_retry(&rate_limit));

    let server = MockServer::respond_once(json!({
        "id": "test-account", "jsonrpc": "2.0",
        "error": { "code": -32603, "message": "Internal error" },
    }));
    let indexer = ZolanaIndexer::new(server.url());
    let internal_error = indexer
        .get_shielded_transactions_by_signature(signature(1), None)
        .expect_err("internal error must surface");
    let _ = server.request();
    assert!(matches!(internal_error, ClientError::IndexerUnavailable(_)));
    assert!(indexer.should_retry(&internal_error));
}

#[test]
fn classifies_non_transient_indexer_errors_without_retry() {
    let server = MockServer::respond_once(json!({
        "id": "test-account", "jsonrpc": "2.0",
        "error": { "code": -32601, "message": "Method not found" },
    }));
    let indexer = ZolanaIndexer::new(server.url());
    let method_not_found = indexer
        .get_shielded_transactions_by_signature(signature(1), None)
        .expect_err("missing method must surface");
    let _ = server.request();
    assert!(matches!(
        method_not_found,
        ClientError::UnsupportedRpcMethod("getShieldedTransactionsBySignature")
    ));
    assert!(!indexer.should_retry(&method_not_found));

    let indexer = ZolanaIndexer::new("not a url");
    let malformed_request = indexer
        .get_shielded_transactions_by_signature(signature(1), None)
        .expect_err("relative URL should be rejected");
    assert!(matches!(malformed_request, ClientError::Indexer(_)));
    assert!(!indexer.should_retry(&malformed_request));
}

#[test]
fn rejects_malformed_output_slot_hash() {
    let tag = bytes32(51);
    let response = rpc_result(json!({
        "context": { "blockTime": 1, "slot": 1 },
        "transactions": [{
            "slot": 1,
            "txSignature": signature(52).to_string(),
            "txViewingPk": null,
            "outputSlots": [{
                "viewTag": encode_hash_string(tag),
                "outputContext": {
                    "hash": bs58::encode([1u8; 31]).into_string(),
                    "tree": encode_pubkey_string(Address::new_from_array(bytes32(53))),
                    "treeId": 3,
                    "leafIndex": 1,
                },
                "payload": STANDARD.encode([1]),
            }],
            "messages": [],
            "nullifiers": [],
            "proofless": true,
        }],
        "nextCursor": null,
    }));
    let server = MockServer::respond_once(response);
    let indexer = ZolanaIndexer::new(server.url());

    let err = indexer
        .get_shielded_transactions_by_tags(vec![tag], None, None, None)
        .expect_err("short output hash must fail");
    let _ = server.request();

    let message = err.to_string();
    assert!(message.contains("wrong size"));
    assert!(message.contains("result.transactions[0].outputSlots[0].outputContext.hash"));
}

#[test]
fn by_signature_error_path_includes_transaction_nesting() {
    let signature = signature(61);
    let response = rpc_result(json!({
        "context": { "blockTime": 1, "slot": 1 },
        "transactions": [{
            "eventIndex": 0,
            "transaction": {
                "slot": 1,
                "txSignature": signature.to_string(),
                "txViewingPk": STANDARD.encode([1u8; 16]),
                "outputSlots": [],
                "messages": [],
                "nullifiers": [],
                "proofless": false,
            },
        }],
    }));
    let server = MockServer::respond_once(response);
    let indexer = ZolanaIndexer::new(server.url());

    let err = indexer
        .get_shielded_transactions_by_signature(signature, None)
        .expect_err("short viewing key must fail");
    let _ = server.request();

    assert!(err
        .to_string()
        .contains("transactions[0].transaction.txViewingPk"));
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
        Self::respond_with_status("200 OK", response)
    }

    fn respond_with_status(status: &'static str, response: Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (request_tx, request_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            request_tx.send(request).unwrap();
            write_http_response(&mut stream, status, response);
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

fn write_http_response(stream: &mut TcpStream, status: &str, body: Value) {
    let body = serde_json::to_string(&body).unwrap();
    write!(
        stream,
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .unwrap();
}
