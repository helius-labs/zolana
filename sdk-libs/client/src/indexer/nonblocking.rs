use std::time::{Duration, Instant};

use async_trait::async_trait;
use solana_address::Address;
use solana_signature::Signature;
use zolana_api::{SerializableSignature, ZolanaApi};

use crate::{
    error::ClientError,
    rpc::{
        AsyncRpc, Context, GetEncryptedUtxosByTagsResponse, GetMerkleProofsResponse,
        GetNonInclusionProofsResponse, GetRingKeyRegistryEntryResponse,
        GetRingKeyRegistryRegisterProofResponse, GetRingSpendRecordResponse,
        GetShieldedTransactionsByNullifiersResponse, GetShieldedTransactionsBySignatureResponse,
        GetShieldedTransactionsByTagsResponse, GetUserRecordsResponse, IndexerRpcConfig,
        RingHistoryOptions, RingMemberProofRequest, RingSpendRecordRequest,
    },
};

use super::{
    conversion::{
        convert_context, convert_encrypted_utxo_match, convert_merkle_proof,
        convert_non_inclusion_proof, convert_shielded_transaction,
        convert_shielded_transactions_by_signature_response,
        convert_shielded_transactions_response, convert_user_records_response, encode_cursor,
        encode_hash, encode_pubkey, ring_history_request,
    },
    error::indexer_error,
};

const MERKLE_PROOF_POLL_TIMEOUT: Duration = Duration::from_secs(60);
/// First wait after an incomplete answer.
///
/// A transfer spends a UTXO the indexer has only just written, so the first
/// attempt often lands a few milliseconds early and this sleep is on the
/// critical path of every transfer. A flat 500ms charged the tail's wait to
/// every caller; starting short and backing off keeps the 60s ceiling for an
/// indexer that is genuinely behind.
const MERKLE_PROOF_POLL_START: Duration = Duration::from_millis(25);
const MERKLE_PROOF_POLL_MAX: Duration = Duration::from_millis(500);

#[derive(Clone, Debug)]
pub struct AsyncZolanaIndexer {
    api: ZolanaApi,
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

#[async_trait]
impl AsyncRpc for AsyncZolanaIndexer {
    fn should_retry(&self, error: &ClientError) -> bool {
        matches!(error, ClientError::IndexerUnavailable(_))
    }

    async fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        wait_for_indexer_async(
            config,
            |response: &GetEncryptedUtxosByTagsResponse| response.context,
            || async {
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
                    output_tree_id: response.output_tree_id,
                    matches: response
                        .matches
                        .into_iter()
                        .enumerate()
                        .map(|(index, item)| convert_encrypted_utxo_match(index, item))
                        .collect::<Result<Vec<_>, _>>()?,
                    next_cursor: response.next_cursor.map(Into::into),
                    scanned_through: response.scanned_through.map(Into::into),
                })
            },
        )
        .await
    }

    async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        wait_for_indexer_async(
            config,
            |response: &GetShieldedTransactionsByTagsResponse| response.context,
            || async {
                let response = self
                    .api
                    .get_shielded_transactions_by_tags(
                        tags.iter().copied().map(encode_hash).collect(),
                        encode_cursor(cursor.clone()),
                        limit.map(u64::from),
                    )
                    .await
                    .map_err(indexer_error)?;

                convert_shielded_transactions_response(response)
            },
        )
        .await
    }

    async fn get_shielded_transactions_by_ring(
        &self,
        options: RingHistoryOptions,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        wait_for_indexer_async(
            config,
            |response: &GetShieldedTransactionsByTagsResponse| response.context,
            || async {
                let response = self
                    .api
                    .get_shielded_transactions(ring_history_request(options.clone())?)
                    .await
                    .map_err(indexer_error)?;
                convert_shielded_transactions_response(response)
            },
        )
        .await
    }

    async fn get_shielded_transactions_by_signature(
        &self,
        signature: Signature,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
        wait_for_indexer_async(
            config,
            |response: &GetShieldedTransactionsBySignatureResponse| response.context,
            || async {
                let response = self
                    .api
                    .get_shielded_transactions_by_signature(SerializableSignature(signature))
                    .await
                    .map_err(indexer_error)?;

                convert_shielded_transactions_by_signature_response(response)
            },
        )
        .await
    }

    async fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        wait_for_indexer_async(
            config,
            |response: &GetShieldedTransactionsByNullifiersResponse| response.context,
            || async {
                let response = self
                    .api
                    .get_shielded_transactions_by_nullifiers(
                        nullifiers.iter().copied().map(encode_hash).collect(),
                        encode_cursor(cursor.clone()),
                        limit.map(u64::from),
                    )
                    .await
                    .map_err(indexer_error)?;

                Ok(GetShieldedTransactionsByNullifiersResponse {
                    context: convert_context(response.context),
                    output_tree_id: response.output_tree_id,
                    transactions: response
                        .transactions
                        .into_iter()
                        .enumerate()
                        .map(|(index, item)| {
                            convert_shielded_transaction(&format!("transactions[{index}]"), item)
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    next_cursor: response.next_cursor.map(Into::into),
                    scanned_through: response.scanned_through.map(Into::into),
                })
            },
        )
        .await
    }

    async fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        let single = || async {
            let response = {
                let _t = crate::prover::timing::Phase::start("merkle_http", 0);
                self.api
                    .get_merkle_proofs(
                        encode_pubkey(tree_account),
                        leaves.iter().copied().map(encode_hash).collect(),
                    )
                    .await
            };
            response
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

        // A caller that named a slot wants that guarantee, so honour it directly and
        // skip the completeness-polling path below.
        if let Some(config) = config.filter(|config| config.require_slot.is_some()) {
            return wait_for_indexer_async(
                Some(config),
                |response: &GetMerkleProofsResponse| response.context,
                single,
            )
            .await;
        }

        let expected = leaves.len();
        let started = Instant::now();
        let mut last_error = None;
        let mut wait = MERKLE_PROOF_POLL_START;
        loop {
            match single().await {
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
            tokio::time::sleep(wait).await;
            wait = (wait * 2).min(MERKLE_PROOF_POLL_MAX);
        }
    }

    async fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        wait_for_indexer_async(
            config,
            |response: &GetNonInclusionProofsResponse| response.context,
            || async {
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
            },
        )
        .await
    }

    async fn get_ring_spend_record(
        &self,
        request: RingSpendRecordRequest,
    ) -> Result<GetRingSpendRecordResponse, ClientError> {
        self.api
            .get_ring_spend_record(request)
            .await
            .map_err(indexer_error)
    }

    async fn get_ring_key_registry_entry(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryEntryResponse, ClientError> {
        self.api
            .get_ring_key_registry_entry(request)
            .await
            .map_err(indexer_error)
    }

    async fn get_ring_key_registry_register_proof(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryRegisterProofResponse, ClientError> {
        self.api
            .get_ring_key_registry_register_proof(request)
            .await
            .map_err(indexer_error)
    }

    async fn get_user_records(
        &self,
        owners: Vec<Address>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetUserRecordsResponse, ClientError> {
        wait_for_indexer_async(
            config,
            |response: &GetUserRecordsResponse| response.context,
            || async {
                let response = self
                    .api
                    .get_user_records(owners.iter().copied().map(encode_pubkey).collect())
                    .await
                    .map_err(indexer_error)?;

                convert_user_records_response(response)
            },
        )
        .await
    }
}

async fn wait_for_indexer_async<T, F, Fut>(
    config: Option<IndexerRpcConfig>,
    context: impl Fn(&T) -> Context,
    request: F,
) -> Result<T, ClientError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, ClientError>>,
{
    let Some((config, required)) = config.and_then(|c| c.require_slot.map(|slot| (c, slot))) else {
        return request().await;
    };
    let mut indexed = 0;
    for delay in std::iter::once(Duration::ZERO).chain(config.poll.backoff()) {
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        let response = request().await?;
        indexed = context(&response).slot;
        if indexed >= required {
            return Ok(response);
        }
    }
    Err(ClientError::IndexerNotCaughtUp {
        required,
        indexed,
        attempts: config.poll.num_retries.saturating_add(1),
    })
}
