use std::time::Duration;

use async_trait::async_trait;
use solana_address::Address;
use solana_signature::Signature;
use spr_api::{SerializableSignature, SprApi};

use crate::{
    error::ClientError,
    rpc::{
        AsyncRpc, Context, GetEncryptedUtxosByTagsResponse, GetMerkleProofsResponse,
        GetNonInclusionProofsResponse, GetShieldedTransactionsByNullifiersResponse,
        GetShieldedTransactionsBySignatureResponse, GetShieldedTransactionsByTagsResponse,
        GetUserRecordsResponse, HistoryFilters, IndexerRpcConfig, PaginationToken,
        RingHistoryOptions,
    },
};

use super::{
    conversion::{
        convert_context, convert_encrypted_utxo_match, convert_merkle_proof,
        convert_non_inclusion_proof, convert_shielded_transactions_by_signature_response,
        convert_shielded_transactions_response, convert_user_records_response, encode_hash,
        encode_pubkey, ring_history_request,
    },
    error::{indexer_error, is_transient_indexer_error},
};

#[derive(Clone, Debug)]
pub struct AsyncSprIndexer {
    api: SprApi,
}

impl AsyncSprIndexer {
    #[cfg(feature = "reqwest")]
    pub fn new(url: impl AsRef<str>) -> Self {
        Self {
            api: SprApi::new(url),
        }
    }

    pub fn with_api(api: SprApi) -> Self {
        Self { api }
    }

    pub fn with_http_trace(mut self) -> Self {
        self.api = self.api.with_http_trace();
        self
    }

    pub fn api(&self) -> &SprApi {
        &self.api
    }
}

#[async_trait]
impl AsyncRpc for AsyncSprIndexer {
    fn should_retry(&self, error: &ClientError) -> bool {
        is_transient_indexer_error(error)
    }

    async fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        pagination_token: Option<PaginationToken>,
        limit: Option<u32>,
        filters: HistoryFilters,
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
                        pagination_token,
                        limit.map(u64::from),
                        filters,
                        config.and_then(|config| config.require_slot),
                    )
                    .await
                    .map_err(indexer_error)?;

                Ok(GetEncryptedUtxosByTagsResponse {
                    context: response.context,
                    output_tree_id: response.output_tree_id,
                    data: response
                        .data
                        .into_iter()
                        .map(|group| {
                            Ok(spr_indexer_api::TransactionOutputs {
                                slot: group.slot,
                                signature: group.signature.0,
                                outputs: group
                                    .outputs
                                    .into_iter()
                                    .enumerate()
                                    .map(|(index, item)| convert_encrypted_utxo_match(index, item))
                                    .collect::<Result<Vec<_>, ClientError>>()?,
                            })
                        })
                        .collect::<Result<Vec<_>, ClientError>>()?,
                    pagination_token: response.pagination_token,
                })
            },
        )
        .await
    }

    async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        pagination_token: Option<PaginationToken>,
        limit: Option<u32>,
        filters: HistoryFilters,
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
                        pagination_token,
                        limit.map(u64::from),
                        filters,
                        config.and_then(|config| config.require_slot),
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
                let mut request = ring_history_request(options.clone())?;
                request.min_context_slot = config.and_then(|config| config.require_slot);
                let response = self
                    .api
                    .get_shielded_transactions(request)
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
        pagination_token: Option<PaginationToken>,
        limit: Option<u32>,
        filters: HistoryFilters,
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
                        pagination_token,
                        limit.map(u64::from),
                        filters,
                        config.and_then(|config| config.require_slot),
                    )
                    .await
                    .map_err(indexer_error)?;

                convert_shielded_transactions_response(response)
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
        wait_for_indexer_async(
            config,
            |response: &GetMerkleProofsResponse| response.context,
            || async {
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
            },
        )
        .await
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

/// One request without `require_slot`. With it, poll on `config.poll` until
/// the indexer answers at or past the slot: an answer below it, a
/// minimum-context-slot refusal and a transient failure retry, and any other
/// error returns at once. An exhausted schedule is classified by its final
/// attempt: a lagging answer is [`ClientError::IndexerNotCaughtUp`], a
/// transient failure [`ClientError::PollTimedOut`] carrying it.
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
    let mut last_error = None;
    for delay in std::iter::once(Duration::ZERO).chain(config.poll.backoff()) {
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        let response = match request().await {
            Ok(response) => response,
            Err(ClientError::IndexerMinimumContextSlot { indexed: observed }) => {
                indexed = indexed.max(observed);
                last_error = None;
                continue;
            }
            Err(error) if is_transient_indexer_error(&error) => {
                last_error = Some(error.to_string());
                continue;
            }
            Err(error) => return Err(error),
        };
        last_error = None;
        indexed = context(&response).slot;
        if indexed >= required {
            return Ok(response);
        }
    }
    let attempts = config.poll.num_retries.saturating_add(1);
    Err(match last_error {
        Some(last_error) => ClientError::PollTimedOut {
            attempts,
            last_error: Some(last_error),
        },
        None => ClientError::IndexerNotCaughtUp {
            required,
            indexed,
            attempts,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn a_minimum_context_error_retries_until_the_required_slot() {
        let calls = AtomicUsize::new(0);
        let response = wait_for_indexer_async(
            Some(IndexerRpcConfig {
                require_slot: Some(10),
                poll: crate::rpc::IndexerPollConfig::new(1, 0, 0),
            }),
            |context: &Context| *context,
            || async {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(ClientError::IndexerMinimumContextSlot { indexed: 9 })
                } else {
                    Ok(Context {
                        slot: 10,
                        block_time: 0,
                    })
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(response.slot, 10);
    }

    fn at_slot_10() -> Option<IndexerRpcConfig> {
        Some(IndexerRpcConfig {
            require_slot: Some(10),
            poll: crate::rpc::IndexerPollConfig::new(1, 0, 0),
        })
    }

    fn answer(slot: u64) -> Result<Context, ClientError> {
        Ok(Context {
            slot,
            block_time: 0,
        })
    }

    fn unavailable() -> Result<Context, ClientError> {
        Err(ClientError::IndexerUnavailable("Internal error".into()))
    }

    /// Runs the slot poll over `script`, one entry per attempt.
    async fn poll(
        script: Vec<Result<Context, ClientError>>,
    ) -> (Result<Context, ClientError>, usize) {
        let script = std::sync::Mutex::new(script.into_iter());
        let calls = AtomicUsize::new(0);
        let result = wait_for_indexer_async(
            at_slot_10(),
            |context: &Context| *context,
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                let next = script.lock().unwrap().next().expect("scripted attempt");
                async move { next }
            },
        )
        .await;
        (result, calls.load(Ordering::SeqCst))
    }

    #[tokio::test]
    async fn a_transient_failure_retries_until_the_required_slot() {
        let (result, calls) = poll(vec![unavailable(), answer(10)]).await;
        assert_eq!(result.unwrap().slot, 10);
        assert_eq!(calls, 2);
    }

    #[tokio::test]
    async fn a_permanent_failure_ends_the_poll_at_once() {
        let (result, calls) = poll(vec![
            Err(ClientError::UnsupportedRpcMethod("getMerkleProofs")),
            answer(10),
        ])
        .await;
        assert!(matches!(
            result,
            Err(ClientError::UnsupportedRpcMethod("getMerkleProofs"))
        ));
        assert_eq!(calls, 1);
    }

    /// The final attempt decides: an answer below the slot is a lag, a
    /// transient failure a timeout carrying that failure.
    #[tokio::test]
    async fn an_exhausted_poll_is_classified_by_its_final_attempt() {
        let (result, _) = poll(vec![unavailable(), answer(9)]).await;
        assert!(
            matches!(
                result,
                Err(ClientError::IndexerNotCaughtUp {
                    required: 10,
                    indexed: 9,
                    attempts: 2
                })
            ),
            "{result:?}"
        );

        let (result, _) = poll(vec![answer(9), unavailable()]).await;
        let Err(ClientError::PollTimedOut {
            attempts: 2,
            last_error: Some(last_error),
        }) = result
        else {
            panic!("expected PollTimedOut, got {result:?}");
        };
        assert!(last_error.contains("Internal error"), "{last_error}");
    }
}
