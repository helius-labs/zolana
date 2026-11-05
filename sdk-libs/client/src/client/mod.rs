//! High-level Zolana client.
//!
//! [`AsyncSprClient`] owns the three services a private transaction
//! needs: the Solana RPC, the indexer and the prover, and is `async`.
//! [`SprClient`] is that client for blocking callers: the same core run by
//! [`Blocking`] on a Tokio runtime, over a blocking Solana RPC lifted by
//! [`OnBlockingPool`] and an `async` indexer, so it is built, used and dropped
//! from plain threads or from inside a multi-thread runtime alike; only a
//! `current_thread` runtime cannot host it. One implementation serves both.
//!
//! A [`Submission`] proves a signed private transaction and builds, or sends
//! and confirms, its native Solana transaction through either client.

mod confirmation;
mod merge;
mod nonblocking;
mod transaction;
mod validation;

use std::sync::Arc;

use spr_api::BlockingRuntime;

use crate::{
    authority::ProofAuthority,
    error::ClientError,
    indexer::AsyncSprIndexer,
    prover::{
        indexed::{PreparedIndexedTransfer, ProofDataSource},
        requests::CircuitRequest,
        witness::AsyncWitnessReader,
        AsyncProverClient, MergeInputs, Proof, Prover, ProverClient, TransferInputs,
    },
    rpc::{
        AsyncRpc, Blocking, ComputeBudgetConfig, IndexerPollConfig, IndexerRpcConfig,
        OnBlockingPool, Rpc,
    },
};
#[cfg(feature = "reqwest")]
use crate::{indexer::SprIndexer, prover::tee::TeePolicy};

pub use merge::{check_merge_record, MergeSubmission, ProvedMerge, MERGE_CU_LIMIT};
pub use transaction::{SignedPrivateTransaction, Submission, UnsignedMessage};
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

/// An indexer of either client: it answers the indexer half of [`AsyncRpc`]
/// and reads input witnesses. [`AsyncSprIndexer`] reads Photon;
/// [`OnBlockingPool`] lifts an in-process blocking indexer, one that answers
/// the indexer half of [`Rpc`] and implements [`WitnessReader`], by default
/// over [`Rpc`]: `impl WitnessReader for MyIndexer {}`. Implemented for every
/// such type.
///
/// [`WitnessReader`]: crate::WitnessReader
pub trait AsyncIndexer: AsyncRpc + AsyncWitnessReader {}

impl<I: AsyncRpc + AsyncWitnessReader> AsyncIndexer for I {}

/// A Solana RPC of the blocking client: a blocking [`Rpc`] that
/// [`OnBlockingPool`] can carry to Tokio's blocking pool. Implemented for
/// every such type.
pub trait BlockingRpc: Rpc + Send + Sync + 'static {}

impl<R: Rpc + Send + Sync + 'static> BlockingRpc for R {}

/// What the blocking client's indexer is built from: an [`AsyncIndexer`] as
/// it is, or a [`Blocking`] one, such as [`SprIndexer`], unwrapped so the
/// client calls the `async` indexer directly.
///
/// [`SprIndexer`]: crate::indexer::SprIndexer
pub trait IntoAsyncIndexer {
    type Indexer: AsyncIndexer;

    /// The indexer, and the runtime it ran on if it had one.
    fn into_async_indexer(self) -> (Self::Indexer, Option<Arc<BlockingRuntime>>);
}

impl<I: AsyncIndexer> IntoAsyncIndexer for I {
    type Indexer = I;

    fn into_async_indexer(self) -> (I, Option<Arc<BlockingRuntime>>) {
        (self, None)
    }
}

impl<I: AsyncIndexer> IntoAsyncIndexer for Blocking<I> {
    type Indexer = I;

    fn into_async_indexer(self) -> (I, Option<Arc<BlockingRuntime>>) {
        let (indexer, runtime) = self.into_parts();
        (indexer, Some(runtime))
    }
}

/// What proves the client's transactions.
enum ProverBackend {
    /// The prover server, boxed: it is several hundred bytes to the custom
    /// prover's pointer.
    Server(Box<AsyncProverClient>),
    /// A prover the caller gave, such as one on the device. It only proves
    /// what the client hands it, so the client always fetches the proof data
    /// itself and no request reaches a prover server.
    Custom(Arc<dyn Prover>),
}

/// The `async` client over a Solana RPC `R` and an indexer `I`.
///
/// The caller should not have to thread Solana RPC, the indexer and the prover
/// through each step. This client owns those services. Proving and native
/// Solana transaction construction happen when a private transaction is
/// signed; submission is the caller's RPC adapter.
pub struct AsyncSprClient<R, I = AsyncSprIndexer> {
    rpc: R,
    indexer: I,
    prover: ProverBackend,
    cu_limit: u32,
    priority_fee_lamports: Option<u64>,
    indexer_config: IndexerRpcConfig,
}

impl<R, I> AsyncSprClient<R, I> {
    /// A client over `rpc`, `indexer` and the prover server `prover`.
    pub fn new(rpc: R, indexer: I, prover: AsyncProverClient) -> Self {
        Self::build(rpc, indexer, ProverBackend::Server(Box::new(prover)))
    }

    /// A client that proves with `prover` instead of a prover server, for
    /// example on the device, so the proof inputs never leave the process.
    /// The client fetches the proof data from `indexer` itself, whatever
    /// [`Self::with_proof_data_source`] says. The prover runs on Tokio's
    /// blocking pool.
    pub fn with_prover(rpc: R, indexer: I, prover: impl Prover + 'static) -> Self {
        Self::build(rpc, indexer, ProverBackend::Custom(Arc::new(prover)))
    }

    fn build(rpc: R, indexer: I, prover: ProverBackend) -> Self {
        Self {
            rpc,
            indexer,
            prover,
            cu_limit: DEFAULT_TRANSACT_CU_LIMIT,
            priority_fee_lamports: None,
            indexer_config: IndexerRpcConfig::default(),
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

    /// Where the prover server reads a transfer's proof data from. A prover
    /// from [`Self::with_prover`] is handed the data by the client, so this
    /// does not apply to it.
    #[must_use]
    pub fn with_proof_data_source(mut self, source: ProofDataSource) -> Self {
        self.prover = match self.prover {
            ProverBackend::Server(prover) => {
                ProverBackend::Server(Box::new(prover.with_proof_data_source(source)))
            }
            custom => custom,
        };
        self
    }

    pub fn rpc(&self) -> &R {
        &self.rpc
    }

    pub fn indexer(&self) -> &I {
        &self.indexer
    }

    /// The data a transfer hands the prover server on its indexed route.
    fn transfer_preparation(&self, signed: &SignedPrivateTransaction) -> TransferPreparation {
        TransferPreparation {
            transaction: signed.transaction.clone(),
            config: self.indexer_config,
        }
    }

    /// The prover server, when a transfer takes its indexed route: the server
    /// fetches the proof data. Otherwise the client fetches the data and hands
    /// it to its prover, server or custom.
    fn indexed_prover(&self) -> Option<&AsyncProverClient> {
        match &self.prover {
            ProverBackend::Server(prover)
                if prover.proof_data_source() == ProofDataSource::Prover =>
            {
                Some(prover.as_ref())
            }
            _ => None,
        }
    }

    /// The runtime key set of the client's prover, if it has one.
    pub(crate) fn key_set(&self) -> Option<&crate::prover::ProvingKeySet> {
        match &self.prover {
            ProverBackend::Server(prover) => prover.key_set(),
            ProverBackend::Custom(prover) => prover.key_set(),
        }
    }

    /// The transfer proof of a transfer off the indexed route.
    async fn prove_transfer(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.prove_request(crate::prover::requests::transfer(inputs)?)
            .await
    }

    /// A proof from the client's prover, server or custom.
    async fn prove_request(&self, request: CircuitRequest) -> Result<Proof, ClientError> {
        match &self.prover {
            ProverBackend::Server(prover) => prover.prove(&request).await,
            ProverBackend::Custom(prover) => {
                prove_on_blocking_pool(Arc::clone(prover), request).await
            }
        }
    }

    /// The merge proof, from the client's prover.
    async fn prove_merge(&self, inputs: &MergeInputs) -> Result<Proof, ClientError> {
        match &self.prover {
            ProverBackend::Server(prover) => prover.prove_merge(inputs).await,
            ProverBackend::Custom(prover) => {
                prove_on_blocking_pool(Arc::clone(prover), crate::prover::requests::merge(inputs)?)
                    .await
            }
        }
    }
}

#[cfg(feature = "reqwest")]
impl<R> AsyncSprClient<R, AsyncSprIndexer> {
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
        Self::new(rpc, AsyncSprIndexer::new(indexer_url.as_ref()), prover)
    }
}

/// The blocking client: an [`AsyncSprClient`] run by [`Blocking`] on a Tokio
/// runtime, over a blocking Solana RPC `R` lifted by [`OnBlockingPool`] and
/// the `async` indexer `I`, [`AsyncSprIndexer`] by default. Every [`Rpc`]
/// call is the `async` client's, run to completion.
pub type SprClient<R, I = AsyncSprIndexer> = Blocking<AsyncSprClient<OnBlockingPool<R>, I>>;

impl<R, I> Blocking<AsyncSprClient<OnBlockingPool<R>, I>> {
    /// A client over `rpc`, `indexer` and the prover server `prover`, run on
    /// the prover client's runtime.
    pub fn new(rpc: R, indexer: impl IntoAsyncIndexer<Indexer = I>, prover: ProverClient) -> Self {
        let (prover, runtime) = prover.into_parts();
        let (indexer, _) = indexer.into_async_indexer();
        Self::with_runtime(
            AsyncSprClient::new(OnBlockingPool::new(rpc), indexer, prover),
            runtime,
        )
    }

    /// See [`AsyncSprClient::with_prover`]. Runs on the indexer's runtime
    /// when it has one, otherwise on a runtime of its own.
    pub fn with_prover(
        rpc: R,
        indexer: impl IntoAsyncIndexer<Indexer = I>,
        prover: impl Prover + 'static,
    ) -> Self {
        let (indexer, runtime) = indexer.into_async_indexer();
        Self::with_runtime(
            AsyncSprClient::with_prover(OnBlockingPool::new(rpc), indexer, prover),
            runtime.unwrap_or_else(|| Arc::new(BlockingRuntime::new())),
        )
    }

    pub fn with_compute_unit_limit(self, cu_limit: u32) -> Self {
        self.map(|client| client.with_compute_unit_limit(cu_limit))
    }

    pub fn with_priority_fee(self, lamports: u64) -> Self {
        self.map(|client| client.with_priority_fee(lamports))
    }

    /// See [`AsyncSprClient::compute_budget`].
    pub fn compute_budget(&self) -> ComputeBudgetConfig {
        self.get_ref().compute_budget()
    }

    pub fn with_indexer_poll_config(self, config: IndexerPollConfig) -> Self {
        self.map(|client| client.with_indexer_poll_config(config))
    }

    pub fn with_indexer_config(self, config: IndexerRpcConfig) -> Self {
        self.map(|client| client.with_indexer_config(config))
    }

    /// See [`AsyncSprClient::with_proof_data_source`].
    #[must_use]
    pub fn with_proof_data_source(self, source: ProofDataSource) -> Self {
        self.map(|client| client.with_proof_data_source(source))
    }

    pub fn rpc(&self) -> &R {
        self.get_ref().rpc().get_ref()
    }

    /// The indexer for blocking calls, on this client's runtime.
    pub fn indexer(&self) -> Blocking<I>
    where
        I: Clone,
    {
        Blocking::with_runtime(self.get_ref().indexer().clone(), self.runtime())
    }
}

#[cfg(feature = "reqwest")]
impl<R> SprClient<R, AsyncSprIndexer> {
    /// The blocking [`AsyncSprClient::from_urls`]: the indexer, the prover
    /// client and this client share one runtime.
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

    /// The blocking [`AsyncSprClient::from_urls_allowing_insecure_http`],
    /// with its warning.
    pub fn from_urls_allowing_insecure_http(
        rpc: R,
        indexer_url: impl AsRef<str>,
        prover_url: impl Into<String>,
        prover_tee: Option<TeePolicy>,
    ) -> Self {
        let (indexer, runtime) = SprIndexer::new(indexer_url.as_ref()).into_parts();
        let prover = AsyncProverClient::new(prover_url.into());
        let prover = match prover_tee {
            Some(policy) => prover.with_tee(policy),
            None => prover,
        };
        Self::new(rpc, indexer, prover.into_blocking_on(runtime))
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

struct TransferPreparation {
    transaction: spr_transaction::instructions::transact::SppProofInputs,
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
