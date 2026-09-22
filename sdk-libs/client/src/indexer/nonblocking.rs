use std::time::Duration;

use async_trait::async_trait;
use solana_address::Address;
use solana_signature::Signature;
use zolana_api::{SerializableSignature, ZolanaApi};

use crate::{
    error::ClientError,
    rpc::{
        AsyncRpc, Context, GetEncryptedUtxosByTagsResponse, GetMerkleProofsResponse,
        GetNonInclusionProofsResponse, GetShieldedTransactionsByNullifiersResponse,
        GetShieldedTransactionsBySignatureResponse, GetShieldedTransactionsByTagsResponse,
        IndexerRpcConfig,
    },
};

use super::{
    conversion::{
        convert_context, convert_encrypted_utxo_match, convert_merkle_proof,
        convert_non_inclusion_proof, convert_shielded_transaction,
        convert_shielded_transactions_by_signature_response,
        convert_shielded_transactions_response, encode_cursor, encode_hash, encode_pubkey,
    },
    error::indexer_error,
};

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
        wait_for_indexer_async(
            config,
            |response: &GetMerkleProofsResponse| response.context,
            || async {
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
