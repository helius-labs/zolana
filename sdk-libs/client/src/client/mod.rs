//! High-level Zolana client.
//!
//! [`AsyncZolanaClient`] owns the three services a private transaction
//! needs: the Solana RPC, the indexer and the prover, and is `async`.
//! [`ZolanaClient`] is that client for blocking callers: the same core run on
//! a Tokio runtime it owns, over a blocking RPC and indexer lifted by
//! [`Blocking`], so it is built, used and dropped from plain threads or from
//! inside a multi-thread runtime alike; only a `current_thread` runtime cannot
//! host it. One implementation serves both.
//!
//! A [`TransactionProofRequest`] proves an encrypted private transaction and builds, or sends
//! and confirms, its native Solana transaction through either client.

mod blocking;
mod confirmation;
mod merge;
mod nonblocking;
mod transaction;
mod validation;

use std::sync::Arc;

use spr_api::BlockingRuntime;

#[cfg(all(feature = "reqwest", feature = "solana-rpc"))]
use crate::indexer::ZolanaIndexer;
#[cfg(feature = "reqwest")]
use crate::prover::tee::TeePolicy;
use crate::{
    error::ClientError,
    indexer::AsyncZolanaIndexer,
    prover::{
        indexed::ProofDataSource,
        requests::CircuitRequest,
        witness::{AsyncWitnessReader, WitnessReader},
        AsyncProverClient, MergeInputs, Proof, Prover,
    },
    rpc::{AsyncRpc, Blocking, ComputeBudgetConfig, IndexerPollConfig, IndexerRpcConfig, Rpc},
};

pub use merge::{check_merge_record, MergeProofRequest, ProvedMerge, MERGE_CU_LIMIT};
pub use transaction::{ProvedTransaction, TransactionProofRequest, UnsignedMessage};
pub use validation::check_service_url;

/// Compute-unit ceiling a private transaction is submitted with unless the
/// caller overrides it. A shielded `Transact` verifies a Groth16 proof
/// on-chain, which does not fit inside the default per-instruction budget.
///
/// Sized from the widest shape this client can send on the rail it sends it on:
/// `submit` proves through `TransferInputs`, and the widest confidential
/// transaction, 49x2 with every input real, consumes
/// 305,340 CU on a validator (`program-tests/spp-test-validator/tests/max_shapes.rs`).
/// The remaining headroom absorbs the per-input `create_nullifier_pdas` cost,
/// which moves with tree state rather than with the shape.
pub const DEFAULT_TRANSACT_CU_LIMIT: u32 = 450_000;

/// An indexer of the `async` client: it answers the indexer half of
/// [`AsyncRpc`] and reads input witnesses. [`AsyncZolanaIndexer`] reads
/// Photon; [`Blocking`] lifts a [`BlockingIndexer`]. Implemented for every
/// such type.
pub trait AsyncIndexer: AsyncRpc + AsyncWitnessReader {}

impl<I: AsyncRpc + AsyncWitnessReader> AsyncIndexer for I {}

/// A Solana RPC of the blocking client: a blocking [`Rpc`] that [`Blocking`]
/// can carry to Tokio's blocking pool. Implemented for every such type.
pub trait BlockingRpc: Rpc + Send + Sync + 'static {}

impl<R: Rpc + Send + Sync + 'static> BlockingRpc for R {}

/// An indexer of the blocking client: it answers the indexer half of [`Rpc`]
/// and reads input witnesses, which [`WitnessReader`] does by default over
/// [`Rpc`], so an in-process indexer needs only `impl WitnessReader for
/// MyIndexer {}`. Implemented for every such type.
pub trait BlockingIndexer: Rpc + WitnessReader + Send + Sync + 'static {}

impl<I: Rpc + WitnessReader + Send + Sync + 'static> BlockingIndexer for I {}

/// What proves the client's transactions.
enum ProverBackend {
    /// The prover server, boxed: it is several hundred bytes to the custom
    /// prover's pointer.
    Server(Box<AsyncProverClient>),
    /// A caller-supplied prover, which may expose a server transport or run
    /// locally on the blocking pool.
    Supplied(Arc<dyn Prover>),
}

/// The `async` client over a Solana RPC `R` and an indexer `I`.
///
/// The caller should not have to thread Solana RPC, the indexer and the prover
/// through each step. Proof requests use these services for preparation,
/// proving and submission. Proved results build Solana messages separately.
pub struct AsyncZolanaClient<R, I = AsyncZolanaIndexer> {
    rpc: R,
    indexer: I,
    prover: ProverBackend,
    cu_limit: u32,
    priority_fee_lamports: Option<u64>,
    indexer_config: IndexerRpcConfig,
    proof_data_source: Option<ProofDataSource>,
}

impl<R, I> AsyncZolanaClient<R, I> {
    /// A client over `rpc`, `indexer` and the prover server `prover`.
    pub fn new(rpc: R, indexer: I, prover: AsyncProverClient) -> Self {
        Self::build(rpc, indexer, ProverBackend::Server(Box::new(prover)))
    }

    /// Use a caller-supplied prover. In-process provers run on Tokio's blocking
    /// pool with data fetched from `indexer`. A `ProverClient` retains its
    /// async transport and configured proof data source.
    pub fn with_prover(rpc: R, indexer: I, prover: impl Prover + 'static) -> Self {
        Self::build(rpc, indexer, ProverBackend::Supplied(Arc::new(prover)))
    }

    fn build(rpc: R, indexer: I, prover: ProverBackend) -> Self {
        Self {
            rpc,
            indexer,
            prover,
            cu_limit: DEFAULT_TRANSACT_CU_LIMIT,
            priority_fee_lamports: None,
            indexer_config: IndexerRpcConfig::default(),
            proof_data_source: None,
        }
    }

    pub fn with_compute_unit_limit(mut self, cu_limit: u32) -> Self {
        self.cu_limit = cu_limit;
        self
    }

    pub fn with_priority_fee(mut self, lamports: u64) -> Self {
        self.priority_fee_lamports = Some(lamports);
        self
    }

    /// The ceilings this client writes into the header of every transaction it
    /// builds.
    pub fn compute_budget(&self) -> ComputeBudgetConfig {
        ComputeBudgetConfig {
            cu_limit: self.cu_limit,
            priority_fee_lamports: self.priority_fee_lamports,
        }
    }

    pub fn with_indexer_poll_config(mut self, config: IndexerPollConfig) -> Self {
        self.indexer_config.poll = config;
        self
    }

    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.indexer_config = config;
        self
    }

    /// Where a server prover reads transfer proof data. In-process provers
    /// receive data fetched by this client.
    #[must_use]
    pub fn with_proof_data_source(mut self, source: ProofDataSource) -> Self {
        self.proof_data_source = Some(source);
        self
    }

    pub fn rpc(&self) -> &R {
        &self.rpc
    }

    pub fn indexer(&self) -> &I {
        &self.indexer
    }

    /// The prover server, when a transfer takes its indexed route: the server
    /// fetches the proof data. Otherwise the client fetches the data and hands
    /// it to its prover, server or custom.
    fn indexed_prover(&self) -> Option<&AsyncProverClient> {
        self.server_prover().filter(|prover| {
            self.proof_data_source.unwrap_or(prover.proof_data_source()) == ProofDataSource::Prover
        })
    }

    fn server_prover(&self) -> Option<&AsyncProverClient> {
        match &self.prover {
            ProverBackend::Server(prover) => Some(prover),
            ProverBackend::Supplied(prover) => prover.server_client(),
        }
    }

    /// A proof from the client's prover, server or custom.
    async fn prove_request(&self, request: CircuitRequest) -> Result<Proof, ClientError> {
        match &self.prover {
            ProverBackend::Server(prover) => prover.prove(&request).await,
            ProverBackend::Supplied(prover) => {
                if let Some(server) = prover.server_client() {
                    return server.prove(&request).await;
                }
                prove_on_blocking_pool(Arc::clone(prover), request).await
            }
        }
    }

    /// The merge proof, from the client's prover.
    async fn prove_merge(&self, inputs: &MergeInputs) -> Result<Proof, ClientError> {
        match &self.prover {
            ProverBackend::Server(prover) => prover.prove_merge(inputs).await,
            ProverBackend::Supplied(prover) => {
                if let Some(server) = prover.server_client() {
                    return server.prove_merge(inputs).await;
                }
                prove_on_blocking_pool(Arc::clone(prover), crate::prover::requests::merge(inputs)?)
                    .await
            }
        }
    }
}

#[cfg(feature = "reqwest")]
impl<R> AsyncZolanaClient<R, AsyncZolanaIndexer> {
    /// Build the Photon indexer and the prover client from their URLs. Both
    /// must be https, or http to loopback: the indexer answers with the
    /// wallet's UTXO set and the prover is sent every proof input.
    /// Supply `Some(policy)` for a remote prover; `None` permits plaintext
    /// only for loopback development.
    pub fn from_urls(
        rpc: R,
        indexer_url: impl AsRef<str>,
        prover_url: impl Into<String>,
        prover_tee: Option<TeePolicy>,
    ) -> Result<Self, ClientError> {
        let indexer_url = indexer_url.as_ref();
        let prover_url = prover_url.into();
        check_service_url(indexer_url, "indexer_url")?;
        check_service_url(&prover_url, "prover_url")?;
        Ok(Self::from_urls_allowing_insecure_http(
            rpc,
            indexer_url,
            prover_url,
            prover_tee,
        ))
    }

    /// [`Self::from_urls`] without the transport check.
    ///
    /// Only for a network that is already private or an explicitly disposable
    /// development profile. A public HTTP indexer exposes the wallet's UTXO
    /// set. The prover still requires the supplied policy off loopback.
    /// Never use this constructor for production funds.
    pub fn from_urls_allowing_insecure_http(
        rpc: R,
        indexer_url: impl AsRef<str>,
        prover_url: impl Into<String>,
        prover_tee: Option<TeePolicy>,
    ) -> Self {
        let prover = AsyncProverClient::new(prover_url.into());
        let prover = match prover_tee {
            Some(policy) => prover.with_tee(policy),
            None => prover,
        };
        Self::new(rpc, AsyncZolanaIndexer::new(indexer_url.as_ref()), prover)
    }
}

/// The blocking client: an [`AsyncZolanaClient`] run on a Tokio runtime it
/// owns, over a blocking Solana RPC `R` and indexer `I`, [`ZolanaIndexer`]
/// by default, each lifted by [`Blocking`].
///
/// [`ZolanaIndexer`]: crate::indexer::ZolanaIndexer
pub struct ZolanaClient<R, I = crate::indexer::ZolanaIndexer> {
    client: AsyncZolanaClient<Blocking<R>, Blocking<I>>,
    runtime: Arc<BlockingRuntime>,
}

impl<R, I> ZolanaClient<R, I> {
    /// Construct services supplied by the caller. Remote provers retain their
    /// async and indexed routes; custom provers run on the blocking pool.
    pub fn from_parts(rpc: R, indexer: I, prover: impl Prover + 'static) -> Self {
        Self {
            client: AsyncZolanaClient::with_prover(
                Blocking::new(rpc),
                Blocking::new(indexer),
                prover,
            ),
            runtime: Arc::new(BlockingRuntime::new()),
        }
    }

    pub fn with_compute_unit_limit(mut self, cu_limit: u32) -> Self {
        self.client = self.client.with_compute_unit_limit(cu_limit);
        self
    }

    pub fn with_priority_fee(mut self, lamports: u64) -> Self {
        self.client = self.client.with_priority_fee(lamports);
        self
    }

    /// See [`AsyncZolanaClient::compute_budget`].
    pub fn compute_budget(&self) -> ComputeBudgetConfig {
        self.client.compute_budget()
    }

    pub fn with_indexer_poll_config(mut self, config: IndexerPollConfig) -> Self {
        self.client = self.client.with_indexer_poll_config(config);
        self
    }

    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.client = self.client.with_indexer_config(config);
        self
    }

    /// See [`AsyncZolanaClient::with_proof_data_source`].
    #[must_use]
    pub fn with_proof_data_source(mut self, source: ProofDataSource) -> Self {
        self.client = self.client.with_proof_data_source(source);
        self
    }

    pub fn rpc(&self) -> &R {
        self.client.rpc.inner()
    }

    pub fn indexer(&self) -> &I {
        self.client.indexer.inner()
    }

    pub(crate) fn block_on<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, ClientError>>,
    ) -> Result<T, ClientError> {
        self.runtime.block_on(future)
    }
}

#[cfg(all(feature = "reqwest", feature = "solana-rpc"))]
impl ZolanaClient<crate::rpc::solana_rpc::SolanaRpc, ZolanaIndexer> {
    /// Use one gateway URL for RPC, indexer and prover requests. Service-specific
    /// paths are appended by their respective adapters.
    pub fn new(url: impl AsRef<str>, prover_tee: Option<TeePolicy>) -> Result<Self, ClientError> {
        Self::from_urls(url.as_ref(), url.as_ref(), url.as_ref(), prover_tee)
    }

    /// The blocking [`AsyncZolanaClient::from_urls`]: the indexer, the prover
    /// client and this client share one runtime.
    /// Supply `Some(policy)` for a remote prover; `None` permits plaintext
    /// only for loopback development.
    pub fn from_urls(
        rpc_url: impl AsRef<str>,
        indexer_url: impl AsRef<str>,
        prover_url: impl AsRef<str>,
        prover_tee: Option<TeePolicy>,
    ) -> Result<Self, ClientError> {
        let indexer_url = indexer_url.as_ref();
        let prover_url = prover_url.as_ref();
        check_service_url(rpc_url.as_ref(), "rpc_url")?;
        check_service_url(indexer_url, "indexer_url")?;
        check_service_url(prover_url, "prover_url")?;
        Ok(Self::from_urls_allowing_insecure_http(
            rpc_url,
            indexer_url,
            prover_url,
            prover_tee,
        ))
    }

    /// The blocking [`AsyncZolanaClient::from_urls_allowing_insecure_http`],
    /// with its warning.
    pub fn from_urls_allowing_insecure_http(
        rpc_url: impl AsRef<str>,
        indexer_url: impl AsRef<str>,
        prover_url: impl AsRef<str>,
        prover_tee: Option<TeePolicy>,
    ) -> Self {
        let indexer = ZolanaIndexer::new(indexer_url.as_ref());
        let prover = AsyncProverClient::new(prover_url.as_ref().to_owned());
        let prover = match prover_tee {
            Some(policy) => prover.with_tee(policy),
            None => prover,
        };
        // The client runs on the indexer's runtime too. A lifted indexer call
        // then nests a `block_on` on that runtime from the blocking pool while
        // the client's own `block_on` holds it; Tokio's current-thread
        // scheduler polls the nested future on its own thread in that case,
        // so the two runtimes it saves do not come with a deadlock.
        let runtime = indexer.runtime();
        Self {
            client: AsyncZolanaClient::new(
                Blocking::new(crate::rpc::solana_rpc::SolanaRpc::new(rpc_url.as_ref())),
                Blocking::new(indexer),
                prover,
            ),
            runtime,
        }
    }
}

/// A custom prover is synchronous and may run for seconds, so it proves on
/// Tokio's blocking pool rather than on the worker that awaits it.
async fn prove_on_blocking_pool(
    prover: Arc<dyn Prover>,
    request: CircuitRequest,
) -> Result<Proof, ClientError> {
    tokio::task::spawn_blocking(move || prover.prove(&request))
        .await
        .map_err(|error| ClientError::Prover(format!("prover task failed: {error}")))?
}
