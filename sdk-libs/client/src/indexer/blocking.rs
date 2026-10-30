use std::sync::Arc;

use crate::{
    error::ClientError,
    rpc::{
        AsyncRpc, GetEncryptedUtxosByTagsResponse, GetMerkleProofsResponse,
        GetNonInclusionProofsResponse, GetShieldedTransactionsByNullifiersResponse,
        GetShieldedTransactionsBySignatureResponse, GetShieldedTransactionsByTagsResponse,
        GetUserRecordsResponse, IndexerRpcConfig, RingHistoryOptions, Rpc,
    },
};
use solana_address::Address;
use solana_signature::Signature;
use spr_api::{BlockingRuntime, BlockingZolanaApi, ZolanaApi};

use super::AsyncZolanaIndexer;

/// Blocking client for the Zolana indexer: an [`AsyncZolanaIndexer`] run on a
/// Tokio runtime of its own, as [`ProverClient`] runs its async client.
#[derive(Clone, Debug)]
pub struct ZolanaIndexer {
    indexer: AsyncZolanaIndexer,
    /// Shared by clones: one runtime per indexer.
    runtime: Arc<BlockingRuntime>,
}

impl ZolanaIndexer {
    /// An indexer whose requests are each bounded by
    /// [`BlockingZolanaApi::new`]'s timeout.
    #[cfg(feature = "reqwest")]
    pub fn new(url: impl AsRef<str>) -> Self {
        Self::with_api(BlockingZolanaApi::new(url))
    }

    pub fn with_api(api: BlockingZolanaApi) -> Self {
        let (api, runtime) = api.into_parts();
        Self {
            indexer: AsyncZolanaIndexer::with_api(api),
            runtime,
        }
    }

    pub fn with_http_trace(mut self) -> Self {
        self.indexer = self.indexer.with_http_trace();
        self
    }

    pub fn api(&self) -> &ZolanaApi {
        self.indexer.api()
    }

    /// The runtime this indexer's calls run on, for a prover client built
    /// beside it.
    pub fn runtime(&self) -> Arc<BlockingRuntime> {
        Arc::clone(&self.runtime)
    }

    pub(crate) fn async_indexer(&self) -> &AsyncZolanaIndexer {
        &self.indexer
    }

    pub(crate) fn block_on<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, ClientError>>,
    ) -> Result<T, ClientError> {
        self.runtime.block_on(future)
    }
}

impl AsyncZolanaIndexer {
    /// This indexer for blocking callers, run on a Tokio runtime of its own.
    /// As with `ZolanaApi::into_blocking`, give it an HTTP client of its own.
    pub fn into_blocking(self) -> ZolanaIndexer {
        ZolanaIndexer {
            indexer: self,
            runtime: Arc::new(BlockingRuntime::new()),
        }
    }
}

impl Rpc for ZolanaIndexer {
    fn should_retry(&self, error: &ClientError) -> bool {
        self.indexer.should_retry(error)
    }

    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        self.block_on(
            self.indexer
                .get_encrypted_utxos_by_tags(tags, cursor, limit, config),
        )
    }

    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.block_on(
            self.indexer
                .get_shielded_transactions_by_tags(tags, cursor, limit, config),
        )
    }

    fn get_shielded_transactions_by_ring(
        &self,
        options: RingHistoryOptions,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.block_on(
            self.indexer
                .get_shielded_transactions_by_ring(options, config),
        )
    }

    fn get_shielded_transactions_by_signature(
        &self,
        signature: Signature,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
        self.block_on(
            self.indexer
                .get_shielded_transactions_by_signature(signature, config),
        )
    }

    fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        self.block_on(
            self.indexer
                .get_shielded_transactions_by_nullifiers(nullifiers, cursor, limit, config),
        )
    }

    fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        self.block_on(self.indexer.get_merkle_proofs(tree_account, leaves, config))
    }

    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        self.block_on(
            self.indexer
                .get_non_inclusion_proofs(tree_account, leaves, config),
        )
    }

    fn get_user_records(
        &self,
        owners: Vec<Address>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetUserRecordsResponse, ClientError> {
        self.block_on(self.indexer.get_user_records(owners, config))
    }
}
