//! Blocking RPC adapter for the Zolana indexer API.

use std::{
    thread::sleep,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use solana_address::Address;
#[cfg(test)]
use solana_signature::Signature;
use zolana_api::{
    Base64String, BlockingZolanaApi, Hash as ApiHash, RingsOutputSlot as ApiOutputSlot,
    SerializablePubkey, ZolanaApi,
};
use zolana_interface::instruction::instruction_data::transact::TransactIxData;
use zolana_keypair::{constants::P256_PUBKEY_LEN, P256Pubkey};
use zolana_transaction::instructions::transact::SppProofInputs;

use crate::{
    error::ClientError,
    prover::{transact::SpendProof, ProverClient},
    retry::IndexerRpcConfig,
    rpc::{
        AsyncRpc, Context, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse,
        GetMerkleProofsResponse, GetNonInclusionProofsResponse,
        GetShieldedTransactionsByTagsResponse, MerkleContext, MerkleProof, NonInclusionProof,
        OutputContext, OutputSlot, Rpc, ShieldedTransaction,
    },
};

const MERKLE_PROOF_POLL_TIMEOUT: Duration = Duration::from_secs(60);
const MERKLE_PROOF_POLL_INTERVAL: Duration = Duration::from_millis(500);

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(i64::MAX)
}

fn with_freshness<T>(
    config: Option<IndexerRpcConfig>,
    block_time: impl Fn(&T) -> i64,
    mut request: impl FnMut() -> Result<T, ClientError>,
) -> Result<T, ClientError> {
    let Some(config) = config.filter(|config| config.wait_for_indexer) else {
        return request();
    };
    let target = now_unix_seconds();
    let mut latest = i64::MIN;
    for delay in std::iter::once(Duration::ZERO).chain(config.poll.backoff()) {
        if !delay.is_zero() {
            sleep(delay);
        }
        let response = request()?;
        latest = block_time(&response);
        if latest >= target {
            return Ok(response);
        }
    }
    Err(ClientError::IndexerNotCaughtUp {
        target,
        latest,
        attempts: config.poll.num_retries.saturating_add(1),
    })
}

async fn with_freshness_async<T, F, Fut>(
    config: Option<IndexerRpcConfig>,
    block_time: impl Fn(&T) -> i64,
    request: F,
) -> Result<T, ClientError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, ClientError>>,
{
    let Some(config) = config.filter(|config| config.wait_for_indexer) else {
        return request().await;
    };
    let target = now_unix_seconds();
    let mut latest = i64::MIN;
    for delay in std::iter::once(Duration::ZERO).chain(config.poll.backoff()) {
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        let response = request().await?;
        latest = block_time(&response);
        if latest >= target {
            return Ok(response);
        }
    }
    Err(ClientError::IndexerNotCaughtUp {
        target,
        latest,
        attempts: config.poll.num_retries.saturating_add(1),
    })
}

#[derive(Clone, Debug)]
pub struct ZolanaIndexer {
    api: BlockingZolanaApi,
}

#[derive(Clone, Debug)]
pub struct AsyncZolanaIndexer {
    api: ZolanaApi,
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

    pub fn prove_transact(
        &self,
        tree: Address,
        proof_inputs: SppProofInputs,
    ) -> Result<TransactIxData, ClientError> {
        let spend_proofs = self.spend_proofs(tree, &proof_inputs)?;
        ProverClient::local().prove_transact(proof_inputs, &spend_proofs)
    }

    fn spend_proofs(
        &self,
        tree: Address,
        proof_inputs: &SppProofInputs,
    ) -> Result<Vec<SpendProof>, ClientError> {
        let inputs = proof_inputs.input_utxo_hashes()?;
        let state_proofs = self
            .get_merkle_proofs(tree, inputs.iter().map(|c| c.utxo_hash).collect(), None)?
            .proofs;
        let nullifier_proofs = self
            .get_non_inclusion_proofs(tree, inputs.iter().map(|c| c.nullifier).collect(), None)?
            .proofs;
        if state_proofs.len() != inputs.len() || nullifier_proofs.len() != inputs.len() {
            return Err(ClientError::Rpc(format!(
                "indexer returned {} state and {} nullifier proofs for {} inputs",
                state_proofs.len(),
                nullifier_proofs.len(),
                inputs.len()
            )));
        }
        Ok(state_proofs
            .into_iter()
            .zip(nullifier_proofs)
            .map(|(state, nullifier)| SpendProof { state, nullifier })
            .collect())
    }
}

impl AsyncZolanaIndexer {
    pub fn new(url: impl AsRef<str>) -> Self {
        Self {
            api: ZolanaApi::new(url),
        }
    }

    pub fn with_api(api: ZolanaApi) -> Self {
        Self { api }
    }

    pub fn with_http_trace(mut self) -> Self {
        self.api = self.api.with_http_trace();
        self
    }

    pub fn api(&self) -> &ZolanaApi {
        &self.api
    }
}

impl Rpc for ZolanaIndexer {
    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        with_freshness(
            config,
            |response: &GetEncryptedUtxosByTagsResponse| response.context.block_time,
            || {
                let response = self
                    .api
                    .get_encrypted_utxos_by_tags(
                        tags.iter().copied().map(encode_hash).collect(),
                        encode_cursor(cursor.clone()),
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
                    next_cursor: response.next_cursor.map(Into::into),
                })
            },
        )
    }

    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        with_freshness(
            config,
            |response: &GetShieldedTransactionsByTagsResponse| response.context.block_time,
            || {
                let response = self
                    .api
                    .get_shielded_transactions_by_tags(
                        tags.iter().copied().map(encode_hash).collect(),
                        encode_cursor(cursor.clone()),
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
                    next_cursor: response.next_cursor.map(Into::into),
                })
            },
        )
    }

    fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        let single = || {
            self.api
                .get_merkle_proofs(
                    encode_pubkey(tree_account),
                    leaves.iter().copied().map(encode_hash).collect(),
                )
                .map_err(indexer_error)
                .map(|response| GetMerkleProofsResponse {
                    context: convert_context(response.context),
                    proofs: response
                        .proofs
                        .into_iter()
                        .map(convert_merkle_proof)
                        .collect(),
                })
        };

        if let Some(config) = config.filter(|config| config.wait_for_indexer) {
            return with_freshness(
                Some(config),
                |response: &GetMerkleProofsResponse| response.context.block_time,
                single,
            );
        }

        let expected = leaves.len();
        let started = Instant::now();
        let mut last_error = None;
        loop {
            match single() {
                Ok(response) if response.proofs.len() >= expected => return Ok(response),
                Ok(_) => {}
                Err(error) => last_error = Some(error),
            }
            if started.elapsed() >= MERKLE_PROOF_POLL_TIMEOUT {
                return Err(last_error.unwrap_or_else(|| {
                    ClientError::Rpc(format!(
                        "merkle proofs for {expected} leaves not indexed within {MERKLE_PROOF_POLL_TIMEOUT:?}"
                    ))
                }));
            }
            sleep(MERKLE_PROOF_POLL_INTERVAL);
        }
    }

    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        with_freshness(
            config,
            |response: &GetNonInclusionProofsResponse| response.context.block_time,
            || {
                let response = self
                    .api
                    .get_non_inclusion_proofs(
                        encode_pubkey(tree_account),
                        leaves.iter().copied().map(encode_hash).collect(),
                    )
                    .map_err(indexer_error)?;

                Ok(GetNonInclusionProofsResponse {
                    context: convert_context(response.context),
                    proofs: response
                        .proofs
                        .into_iter()
                        .map(convert_non_inclusion_proof)
                        .collect(),
                })
            },
        )
    }
}

#[async_trait]
impl AsyncRpc for AsyncZolanaIndexer {
    async fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        with_freshness_async(config, |response: &GetEncryptedUtxosByTagsResponse| response.context.block_time, || async {
            let response = self
                .api
                .get_encrypted_utxos_by_tags(
                    tags.iter().copied().map(encode_hash).collect(),
                    encode_cursor(cursor.clone()),
                    limit.map(u64::from),
                )
                .await
                .map_err(indexer_error)?;

            Ok(GetEncryptedUtxosByTagsResponse {
                context: convert_context(response.context),
                matches: response
                    .matches
                    .into_iter()
                    .enumerate()
                    .map(|(index, item)| convert_encrypted_utxo_match(index, item))
                    .collect::<Result<Vec<_>, _>>()?,
                next_cursor: response.next_cursor.map(Into::into),
            })
        })
        .await
    }

    async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        with_freshness_async(config, |response: &GetShieldedTransactionsByTagsResponse| response.context.block_time, || async {
            let response = self
                .api
                .get_shielded_transactions_by_tags(
                    tags.iter().copied().map(encode_hash).collect(),
                    encode_cursor(cursor.clone()),
                    limit.map(u64::from),
                )
                .await
                .map_err(indexer_error)?;

            Ok(GetShieldedTransactionsByTagsResponse {
                context: convert_context(response.context),
                transactions: response
                    .transactions
                    .into_iter()
                    .enumerate()
                    .map(|(index, item)| convert_shielded_transaction(index, item))
                    .collect::<Result<Vec<_>, _>>()?,
                next_cursor: response.next_cursor.map(Into::into),
            })
        })
        .await
    }

    async fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        with_freshness_async(config, |response: &GetMerkleProofsResponse| response.context.block_time, || async {
            let response = self
                .api
                .get_merkle_proofs(
                    encode_pubkey(tree_account),
                    leaves.iter().copied().map(encode_hash).collect(),
                )
                .await
                .map_err(indexer_error)?;

            Ok(GetMerkleProofsResponse {
                context: convert_context(response.context),
                proofs: response
                    .proofs
                    .into_iter()
                    .map(convert_merkle_proof)
                    .collect(),
            })
        })
        .await
    }

    async fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        with_freshness_async(config, |response: &GetNonInclusionProofsResponse| response.context.block_time, || async {
            let response = self
                .api
                .get_non_inclusion_proofs(
                    encode_pubkey(tree_account),
                    leaves.iter().copied().map(encode_hash).collect(),
                )
                .await
                .map_err(indexer_error)?;

            Ok(GetNonInclusionProofsResponse {
                context: convert_context(response.context),
                proofs: response
                    .proofs
                    .into_iter()
                    .map(convert_non_inclusion_proof)
                    .collect(),
            })
        })
        .await
    }
}

fn indexer_error(error: zolana_api::ApiError) -> ClientError {
    ClientError::Indexer(error.to_string())
}

fn convert_context(context: zolana_api::Context) -> Context {
    Context {
        block_time: context.block_time,
    }
}

fn convert_encrypted_utxo_match(
    index: usize,
    item: zolana_api::EncryptedUtxoMatch,
) -> Result<EncryptedUtxoMatch, ClientError> {
    Ok(EncryptedUtxoMatch {
        slot: item.slot,
        tx_signature: item.tx_signature.0,
        output_slot: convert_output_slot(item.output_slot),
        tx_viewing_pk: decode_optional_p256(
            item.tx_viewing_pk,
            &format!("matches[{index}].tx_viewing_pk"),
        )?,
        salt: decode_optional_salt(item.salt, &format!("matches[{index}].salt"))?,
    })
}

fn convert_shielded_transaction(
    index: usize,
    item: zolana_api::ShieldedTransaction,
) -> Result<ShieldedTransaction, ClientError> {
    Ok(ShieldedTransaction {
        slot: item.slot,
        tx_signature: item.tx_signature.0,
        tx_viewing_pk: decode_optional_p256(
            item.tx_viewing_pk,
            &format!("transactions[{index}].tx_viewing_pk"),
        )?,
        salt: decode_optional_salt(item.salt, &format!("transactions[{index}].salt"))?,
        output_slots: item
            .output_slots
            .into_iter()
            .map(convert_output_slot)
            .collect(),
        messages: item
            .messages
            .into_iter()
            .map(|message| zolana_event::MessageData {
                view_tag: message.view_tag.into(),
                data: message.payload.into(),
            })
            .collect(),
        nullifiers: item.nullifiers.into_iter().map(Into::into).collect(),
        proofless: item.proofless,
    })
}

fn convert_output_slot(slot: ApiOutputSlot) -> OutputSlot {
    OutputSlot {
        view_tag: slot.view_tag.into(),
        output_context: convert_output_context(slot.output_context),
        payload: slot.payload.into(),
    }
}

fn convert_output_context(context: zolana_api::RingsOutputContext) -> OutputContext {
    OutputContext {
        hash: context.hash.into(),
        tree: Address::new_from_array(context.tree.0.to_bytes()),
        leaf_index: context.leaf_index,
    }
}

fn convert_merkle_proof(proof: zolana_api::MerkleProof) -> MerkleProof {
    MerkleProof {
        leaf: proof.leaf.into(),
        merkle_context: convert_merkle_context(proof.merkle_context),
        path: proof.path.into_iter().map(Into::into).collect(),
        leaf_index: proof.leaf_index,
        root: proof.root.into(),
        root_seq: proof.root_seq,
        root_index: proof.root_index,
    }
}

fn convert_non_inclusion_proof(proof: zolana_api::NonInclusionProof) -> NonInclusionProof {
    NonInclusionProof {
        leaf: proof.leaf.into(),
        merkle_context: convert_merkle_context(proof.merkle_context),
        path: proof.path.into_iter().map(Into::into).collect(),
        low_element: proof.low_element.into(),
        low_element_index: proof.low_element_index,
        high_element: proof.high_element.into(),
        high_element_index: proof.high_element_index,
        root: proof.root.into(),
        root_seq: proof.root_seq,
        root_index: proof.root_index,
    }
}

fn convert_merkle_context(context: zolana_api::MerkleContext) -> MerkleContext {
    MerkleContext {
        tree_type: context.tree_type,
        tree: Address::new_from_array(context.tree.0.to_bytes()),
    }
}

fn encode_hash(hash: [u8; 32]) -> ApiHash {
    ApiHash::from(hash)
}

fn encode_pubkey(address: Address) -> SerializablePubkey {
    SerializablePubkey::from(address.to_bytes())
}

fn encode_cursor(cursor: Option<Vec<u8>>) -> Option<Base64String> {
    cursor.map(Base64String::from)
}

fn decode_optional_p256(
    value: Option<Base64String>,
    field: &str,
) -> Result<Option<P256Pubkey>, ClientError> {
    value
        .map(|value| {
            let bytes = fixed_bytes(value.0, P256_PUBKEY_LEN, field)?;
            P256Pubkey::from_bytes(bytes).map_err(|error| decode_error(field, error))
        })
        .transpose()
}

fn decode_optional_salt(
    value: Option<Base64String>,
    field: &str,
) -> Result<Option<[u8; 16]>, ClientError> {
    value
        .map(|value| fixed_bytes(value.0, 16, field))
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

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use p256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
    use serde_json::{json, Value};

    use super::*;

    #[test]
    fn decodes_compressed_p256_pubkey() {
        let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let public = secret.public_key();
        let point = public.to_encoded_point(true);
        let key = decode_optional_p256(
            Some(Base64String(point.as_bytes().to_vec())),
            "tx_viewing_pk",
        )
        .unwrap()
        .unwrap();

        assert_eq!(key.as_bytes(), point.as_bytes());
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
            "context": { "block_time": 42 },
            "matches": [{
                "slot": 7,
                "tx_signature": signature.to_string(),
                "output_slot": {
                    "view_tag": encode_hash_string(tag_a),
                    "output_context": {
                        "hash": encode_hash_string(utxo_hash),
                        "tree": encode_pubkey_string(output_tree),
                        "leaf_index": 11,
                    },
                    "payload": STANDARD.encode([8, 9, 10]),
                },
                "tx_viewing_pk": STANDARD.encode(&tx_viewing_pk_bytes),
            }],
            "next_cursor": STANDARD.encode([5, 6]),
        }));
        let server = MockServer::respond_once(response);
        let indexer = ZolanaIndexer::new(server.url());

        let got = indexer
            .get_encrypted_utxos_by_tags(vec![tag_a, tag_b], Some(vec![1, 2, 3]), Some(7), None)
            .expect("encrypted UTXO lookup");
        let request = server.request();

        assert_eq!(request.path, "/get_encrypted_utxos_by_tags");
        assert_json_rpc_request(&request.body, "get_encrypted_utxos_by_tags");
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
                context: Context { block_time: 42 },
                matches: vec![EncryptedUtxoMatch {
                    slot: 7,
                    tx_signature: signature,
                    output_slot: OutputSlot {
                        view_tag: tag_a,
                        output_context: OutputContext {
                            hash: utxo_hash,
                            tree: output_tree,
                            leaf_index: 11,
                        },
                        payload: vec![8, 9, 10],
                    },
                    tx_viewing_pk: Some(tx_viewing_pk),
                    salt: None,
                }],
                next_cursor: Some(vec![5, 6]),
            }
        );
    }

    #[test]
    fn get_shielded_transactions_by_tags_maps_output_hashes_and_nullifiers() {
        let tag = bytes32(11);
        let output_hash = bytes32(12);
        let output_tree = Address::new_from_array(bytes32(15));
        let nullifier = bytes32(13);
        let signature = signature(14);
        let response = rpc_result(json!({
            "context": { "block_time": 51 },
            "transactions": [{
                "slot": 50,
                "tx_signature": signature.to_string(),
                "tx_viewing_pk": null,
                "output_slots": [{
                    "view_tag": encode_hash_string(tag),
                    "output_context": {
                        "hash": encode_hash_string(output_hash),
                        "tree": encode_pubkey_string(output_tree),
                        "leaf_index": 16,
                    },
                    "payload": STANDARD.encode([21, 22]),
                }],
                "messages": [],
                "nullifiers": [encode_hash_string(nullifier)],
                "proofless": true,
            }],
            "next_cursor": STANDARD.encode([23]),
        }));
        let server = MockServer::respond_once(response);
        let indexer = ZolanaIndexer::new(server.url());

        let got = indexer
            .get_shielded_transactions_by_tags(vec![tag], None, Some(1), None)
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
        assert_eq!(
            got,
            GetShieldedTransactionsByTagsResponse {
                context: Context { block_time: 51 },
                transactions: vec![ShieldedTransaction {
                    slot: 50,
                    tx_signature: signature,
                    tx_viewing_pk: None,
                    salt: None,
                    output_slots: vec![OutputSlot {
                        view_tag: tag,
                        output_context: OutputContext {
                            hash: output_hash,
                            tree: output_tree,
                            leaf_index: 16,
                        },
                        payload: vec![21, 22],
                    }],
                    nullifiers: vec![nullifier],
                    proofless: true,
                    messages: vec![],
                }],
                next_cursor: Some(vec![23]),
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
            "context": { "block_time": 80 },
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
            .get_merkle_proofs(tree, vec![leaf_a], None)
            .expect("merkle proofs");
        let request = server.request();

        assert_eq!(request.path, "/get_merkle_proofs");
        assert_json_rpc_request(&request.body, "get_merkle_proofs");
        assert_eq!(
            request.body["params"],
            json!({
                "tree_account": encode_pubkey_string(tree),
                "leaves": [encode_hash_string(leaf_a)],
            })
        );
        assert_eq!(
            got,
            GetMerkleProofsResponse {
                context: Context { block_time: 80 },
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
            "context": { "block_time": 90 },
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
            .get_non_inclusion_proofs(tree, vec![leaf], None)
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
        assert_eq!(
            got,
            GetNonInclusionProofsResponse {
                context: Context { block_time: 90 },
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
    fn rejects_malformed_output_slot_hash() {
        let tag = bytes32(51);
        let response = rpc_result(json!({
            "context": { "block_time": 1 },
            "transactions": [{
                "slot": 1,
                "tx_signature": signature(52).to_string(),
                "tx_viewing_pk": null,
                "output_slots": [{
                    "view_tag": encode_hash_string(tag),
                    "output_context": {
                        "hash": bs58::encode([1u8; 31]).into_string(),
                        "tree": encode_pubkey_string(Address::new_from_array(bytes32(53))),
                        "leaf_index": 1,
                    },
                    "payload": STANDARD.encode([1]),
                }],
                "messages": [],
                "nullifiers": [],
                "proofless": true,
            }],
            "next_cursor": null,
        }));
        let server = MockServer::respond_once(response);
        let indexer = ZolanaIndexer::new(server.url());

        let err = indexer
            .get_shielded_transactions_by_tags(vec![tag], None, None, None)
            .expect_err("short output hash must fail");
        let _ = server.request();

        let message = err.to_string();
        assert!(message.contains("wrong size"));
        assert!(message.contains("result.transactions[0].output_slots[0].output_context.hash"));
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
