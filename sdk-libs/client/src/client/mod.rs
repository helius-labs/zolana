//! High-level Zolana client.
//!
//! [`ZolanaClient`] owns Solana RPC, Photon, and the prover.
//! [`sign_private_transaction`] returns a signed native Solana transaction.
//! Submit that transaction through the client's RPC adapter, then confirm on-chain and wait
//! for Photon indexing with [`ZolanaClient::confirm_private_transaction`].

mod blocking;
mod confirmation;
mod nonblocking;
mod transaction;
mod validation;

use std::sync::OnceLock;

use crate::{
    authority::ProofAuthority,
    error::ClientError,
    indexer::{AsyncZolanaIndexer, ZolanaIndexer},
    prover::{
        indexed::{PreparedIndexedTransfer, ProvenIndexedTransfer},
        AsyncProverClient, ProverClient,
    },
    rpc::{ComputeBudgetConfig, IndexerPollConfig, IndexerRpcConfig},
};

pub use transaction::SignedPrivateTransaction;
use validation::check_service_url;

/// Compute-unit ceiling a private transaction is submitted with unless the
/// caller overrides it. A shielded `Transact` verifies a Groth16 proof
/// on-chain, which does not fit inside the default per-instruction budget.
///
/// Sized from the widest shape this client can send on the rail it sends it on:
/// `submit` proves through `TransferInputs`, and
/// `program-tests/shielded-pool/CU_BENCHMARK.md` measures "Transfer eddsa 36x2"
/// at 292,473 CU for `process_instruction`. The remaining headroom absorbs the
/// per-input `create_nullifier_pdas` cost, which moves with tree state rather
/// than with the shape. The ring P256 rail is more expensive again, but it
/// carries its own ceiling and does not come through here.
pub const DEFAULT_TRANSACT_CU_LIMIT: u32 = 450_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProofDataSource {
    #[default]
    Client,
    Prover,
}

/// Unified client for private transaction proving and submission helpers.
///
/// The caller should not have to thread Solana RPC, Photon, and prover handles
/// through each step. This client owns those services. Proving and native Solana
/// transaction construction happen during [`sign_private_transaction`]; submission
/// is the caller's RPC adapter.
pub struct ZolanaClient<R> {
    rpc: R,
    indexer: OnceLock<ZolanaIndexer>,
    prover: OnceLock<ProverClient>,
    blocking_indexer_url: Option<String>,
    blocking_prover_url: Option<String>,
    async_indexer: AsyncZolanaIndexer,
    async_prover: AsyncProverClient,
    cu_limit: u32,
    cu_price_micro_lamports: Option<u64>,
    indexer_config: IndexerRpcConfig,
    proof_data_source: ProofDataSource,
}

impl<R> ZolanaClient<R> {
    pub fn new(
        rpc: R,
        indexer: ZolanaIndexer,
        prover: ProverClient,
        async_indexer: AsyncZolanaIndexer,
        async_prover: AsyncProverClient,
    ) -> Self {
        Self {
            rpc,
            indexer: OnceLock::from(indexer),
            prover: OnceLock::from(prover),
            blocking_indexer_url: None,
            blocking_prover_url: None,
            async_indexer,
            async_prover,
            cu_limit: DEFAULT_TRANSACT_CU_LIMIT,
            cu_price_micro_lamports: None,
            indexer_config: IndexerRpcConfig::default(),
            proof_data_source: ProofDataSource::default(),
        }
    }

    /// Build both async and blocking service adapters from their URLs.
    pub fn from_urls(
        rpc: R,
        indexer_url: impl AsRef<str>,
        prover_url: impl Into<String>,
    ) -> Result<Self, ClientError> {
        let indexer_url = indexer_url.as_ref().to_string();
        let prover_url = prover_url.into();
        check_service_url(&indexer_url, "indexer_url")?;
        check_service_url(&prover_url, "prover_url")?;
        Ok(Self::from_urls_allowing_insecure_http(
            rpc,
            indexer_url,
            prover_url,
        ))
    }

    /// [`Self::from_urls`] without the transport check.
    ///
    /// Only for a network that is already private or an explicitly disposable
    /// development profile that accepts zero transport-privacy. On a public
    /// endpoint this publishes the wallet's UTXO set and every proof input in
    /// the clear. Never use this constructor for production funds.
    pub fn from_urls_allowing_insecure_http(
        rpc: R,
        indexer_url: impl AsRef<str>,
        prover_url: impl Into<String>,
    ) -> Self {
        let indexer_url = indexer_url.as_ref().to_string();
        let prover_url = prover_url.into();
        Self {
            rpc,
            indexer: OnceLock::new(),
            prover: OnceLock::new(),
            blocking_indexer_url: Some(indexer_url.clone()),
            blocking_prover_url: Some(prover_url.clone()),
            async_indexer: AsyncZolanaIndexer::new(indexer_url),
            async_prover: AsyncProverClient::new(prover_url),
            cu_limit: DEFAULT_TRANSACT_CU_LIMIT,
            cu_price_micro_lamports: None,
            indexer_config: IndexerRpcConfig::default(),
            proof_data_source: ProofDataSource::default(),
        }
    }

    pub fn with_compute_unit_limit(mut self, cu_limit: u32) -> Self {
        self.cu_limit = cu_limit;
        self
    }

    pub fn with_compute_unit_price(mut self, micro_lamports: u64) -> Self {
        self.cu_price_micro_lamports = Some(micro_lamports);
        self
    }

    /// The ceilings this client writes into the header of every transaction it
    /// builds.
    pub fn compute_budget(&self) -> ComputeBudgetConfig {
        ComputeBudgetConfig {
            cu_limit: self.cu_limit,
            cu_price_micro_lamports: self.cu_price_micro_lamports,
        }
    }

    pub fn with_indexer_poll_config(mut self, config: IndexerPollConfig) -> Self {
        self.indexer_config.poll = config;
        self
    }

    #[must_use]
    pub fn with_proof_data_source(mut self, source: ProofDataSource) -> Self {
        self.proof_data_source = source;
        self
    }

    fn indexed_transfer(
        &self,
        preparation: TransferPreparation,
        authority: &dyn ProofAuthority,
    ) -> Result<ProvenIndexedTransfer, ClientError> {
        let prepared = preparation.prepare(authority)?;
        let proof = self.blocking_prover().prove_indexed(prepared.request())?;
        prepared.finish(proof)
    }

    async fn indexed_transfer_async(
        &self,
        preparation: TransferPreparation,
        authority: &dyn ProofAuthority,
    ) -> Result<ProvenIndexedTransfer, ClientError> {
        let prepared = preparation.prepare(authority)?;
        let proof = self.async_prover.prove_indexed(prepared.request()).await?;
        prepared.finish(proof)
    }

    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.indexer_config = config;
        self
    }

    pub fn rpc(&self) -> &R {
        &self.rpc
    }

    pub fn indexer(&self) -> &ZolanaIndexer {
        self.blocking_indexer()
    }

    fn blocking_indexer(&self) -> &ZolanaIndexer {
        self.indexer.get_or_init(|| {
            ZolanaIndexer::new(
                self.blocking_indexer_url
                    .as_deref()
                    .expect("blocking indexer URL is set when the client is deferred"),
            )
        })
    }

    fn blocking_prover(&self) -> &ProverClient {
        self.prover.get_or_init(|| {
            ProverClient::new(
                self.blocking_prover_url
                    .clone()
                    .expect("blocking prover URL is set when the client is deferred"),
            )
        })
    }
}

struct TransferPreparation {
    transaction: zolana_transaction::instructions::transact::SppProofInputs,
    config: IndexerRpcConfig,
}

impl TransferPreparation {
    fn prepare(
        self,
        authority: &dyn ProofAuthority,
    ) -> Result<PreparedIndexedTransfer, ClientError> {
        let prepared = PreparedIndexedTransfer::new(self.transaction, authority)?;
        Ok(match self.config.require_slot {
            Some(slot) => prepared.with_min_context_slot(slot),
            None => prepared,
        })
    }
}
