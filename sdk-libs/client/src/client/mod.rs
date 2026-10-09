//! High-level Zolana client.
//!
//! [`ZolanaClient`] owns the three services a private transaction needs: the
//! Solana RPC, the indexer and the prover. The indexer fixes the client's mode:
//! over a [`BlockingIndexer`], [`ZolanaIndexer`] by default, the client blocks
//! and implements [`Rpc`]; over an [`AsyncIndexer`], [`AsyncZolanaIndexer`] by
//! default, it is `async` and implements [`AsyncRpc`], and [`AsyncZolanaClient`]
//! names it. The blocking client's indexer and prover run on a Tokio runtime
//! of their own, so it is built, used and dropped from plain threads or from
//! inside a multi-thread runtime alike; only a `current_thread` runtime cannot
//! host it.
//!
//! Sign a private transaction into a native Solana transaction, submit it
//! through the client's RPC, then confirm on chain and wait for the indexer
//! with [`ZolanaClient::confirm_private_transaction_sync`] or
//! [`AsyncZolanaClient::confirm_private_transaction`].

mod blocking;
mod confirmation;
mod nonblocking;
mod transaction;
mod validation;

use std::sync::Arc;

use crate::{
    authority::ProofAuthority,
    error::ClientError,
    indexer::{AsyncZolanaIndexer, ZolanaIndexer},
    prover::{
        indexed::{PreparedIndexedTransfer, ProofDataSource},
        witness::{AsyncWitnessReader, WitnessReader},
        AsyncProverClient, Proof, Prover, ProverClient, ProverServer, TransferInputs,
    },
    rpc::{AsyncRpc, ComputeBudgetConfig, IndexerPollConfig, IndexerRpcConfig, Rpc},
};

pub use transaction::{SignedPrivateTransaction, Submission};
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
/// which moves with tree state rather than with the shape. The ring P256 rail
/// is more expensive again (356,230 CU at 49x2), but it carries its own
/// ceiling and does not come through here.
pub const DEFAULT_TRANSACT_CU_LIMIT: u32 = 450_000;

/// An indexer a [`ZolanaClient`] is built over. The indexer fixes the
/// client's mode: a [`BlockingIndexer`] gives the blocking client and an
/// [`AsyncIndexer`] the `async` one, and each names the prover client of its
/// kind. [`ZolanaIndexer`] and [`AsyncZolanaIndexer`] read Photon; an
/// in-process indexer, such as a test harness, implements this with [`Rpc`]
/// and [`WitnessReader`] and is a client's indexer the same way.
pub trait Indexer {
    type ProverClient: ProverServer;
}

/// An indexer of the blocking client: it answers the indexer half of [`Rpc`]
/// and reads input witnesses, which [`WitnessReader`] does by default over
/// [`Rpc`]. Implemented for every such type.
pub trait BlockingIndexer: Indexer<ProverClient = ProverClient> + Rpc + WitnessReader {}

impl<I: Indexer<ProverClient = ProverClient> + Rpc + WitnessReader> BlockingIndexer for I {}

/// An indexer of the `async` client; see [`BlockingIndexer`].
pub trait AsyncIndexer:
    Indexer<ProverClient = AsyncProverClient> + AsyncRpc + AsyncWitnessReader
{
}

impl<I: Indexer<ProverClient = AsyncProverClient> + AsyncRpc + AsyncWitnessReader> AsyncIndexer
    for I
{
}

impl Indexer for ZolanaIndexer {
    type ProverClient = ProverClient;
}

impl Indexer for AsyncZolanaIndexer {
    type ProverClient = AsyncProverClient;
}

/// A [`ZolanaClient`] over an [`AsyncZolanaIndexer`]: the `async` client.
pub type AsyncZolanaClient<R> = ZolanaClient<R, AsyncZolanaIndexer>;

/// What proves the client's transactions.
enum ProverBackend<S> {
    /// The prover server.
    Server(S),
    /// A prover the caller gave, such as one on the device. It only proves
    /// what the client hands it, so the client always fetches the proof data
    /// itself and no request reaches a prover server.
    Custom(Arc<dyn Prover>),
}

/// Unified client for private transaction proving and submission helpers.
///
/// The caller should not have to thread Solana RPC, the indexer and the prover
/// through each step. This client owns those services; the indexer `I` fixes
/// whether it blocks or is `async`. Proving and native Solana transaction
/// construction happen when a private transaction is signed; submission is
/// the caller's RPC adapter.
pub struct ZolanaClient<R, I: Indexer = ZolanaIndexer> {
    rpc: R,
    indexer: I,
    prover: ProverBackend<I::ProverClient>,
    cu_limit: u32,
    priority_fee_lamports: Option<u64>,
    indexer_config: IndexerRpcConfig,
}

impl<R, I: Indexer> ZolanaClient<R, I> {
    /// A client over `rpc`, `indexer` and the prover server `prover`.
    pub fn new(rpc: R, indexer: I, prover: I::ProverClient) -> Self {
        Self::build(rpc, indexer, ProverBackend::Server(prover))
    }

    /// A client that proves with `prover` instead of a prover server, for
    /// example on the device, so the proof inputs never leave the process.
    /// The client fetches the proof data from `indexer` itself, whatever
    /// [`Self::with_proof_data_source`] says. The `async` client runs the prover
    /// on Tokio's blocking pool.
    pub fn with_prover(rpc: R, indexer: I, prover: impl Prover + 'static) -> Self {
        Self::build(rpc, indexer, ProverBackend::Custom(Arc::new(prover)))
    }

    fn build(rpc: R, indexer: I, prover: ProverBackend<I::ProverClient>) -> Self {
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
                ProverBackend::Server(prover.with_proof_data_source(source))
            }
            custom => custom,
        };
        self
    }

    /// The data a transfer hands the prover server on its indexed route.
    fn transfer_preparation(&self, signed: &SignedPrivateTransaction) -> TransferPreparation {
        TransferPreparation {
            transaction: signed.transaction.clone(),
            config: self.indexer_config,
        }
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
    fn indexed_prover(&self) -> Option<&I::ProverClient> {
        match &self.prover {
            ProverBackend::Server(prover)
                if prover.proof_data_source() == ProofDataSource::Prover =>
            {
                Some(prover)
            }
            _ => None,
        }
    }
}

/// A Photon client, built from the indexer's URL: [`ZolanaIndexer`] or
/// [`AsyncZolanaIndexer`]. Sealed, since only these are reached through a
/// URL; any other [`Indexer`] is built by its own means and passed to
/// [`ZolanaClient::new`].
#[cfg(feature = "reqwest")]
pub trait PhotonIndexer: Indexer + sealed::Sealed {
    fn from_url(url: &str) -> Self;
    /// The prover client at `url`, run with this indexer: on the blocking
    /// indexer's runtime, so a client built from URLs owns one runtime.
    fn prover_client(&self, url: String) -> Self::ProverClient;
}

#[cfg(feature = "reqwest")]
mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::indexer::ZolanaIndexer {}
    impl Sealed for crate::indexer::AsyncZolanaIndexer {}
}

#[cfg(feature = "reqwest")]
impl PhotonIndexer for ZolanaIndexer {
    fn from_url(url: &str) -> Self {
        ZolanaIndexer::new(url)
    }

    fn prover_client(&self, url: String) -> ProverClient {
        AsyncProverClient::new(url).into_blocking_on(self.runtime())
    }
}

#[cfg(feature = "reqwest")]
impl PhotonIndexer for AsyncZolanaIndexer {
    fn from_url(url: &str) -> Self {
        AsyncZolanaIndexer::new(url)
    }

    fn prover_client(&self, url: String) -> AsyncProverClient {
        AsyncProverClient::new(url)
    }
}

#[cfg(feature = "reqwest")]
impl<R, I: PhotonIndexer> ZolanaClient<R, I> {
    /// Build the Photon indexer and the prover client from their URLs. Both
    /// must be https, or http to loopback: the indexer answers with the
    /// wallet's UTXO set and the prover is sent every proof input.
    ///
    /// No argument names the mode, and Rust does not infer a default type
    /// parameter, so name it where nothing else does:
    /// `ZolanaClient::<_>::from_urls(..)` builds the blocking client and
    /// `AsyncZolanaClient::from_urls(..)` the `async` one.
    pub fn from_urls(
        rpc: R,
        indexer_url: impl AsRef<str>,
        prover_url: impl Into<String>,
    ) -> Result<Self, ClientError> {
        let indexer_url = indexer_url.as_ref();
        let prover_url = prover_url.into();
        check_service_url(indexer_url, "indexer_url")?;
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
        let indexer = I::from_url(indexer_url.as_ref());
        let prover = indexer.prover_client(prover_url.into());
        Self::new(rpc, indexer, prover)
    }
}

impl<R, I: BlockingIndexer> ZolanaClient<R, I> {
    /// The prover of a transfer off the indexed route.
    fn prover(&self) -> &dyn Prover {
        match &self.prover {
            ProverBackend::Server(prover) => prover,
            ProverBackend::Custom(prover) => prover.as_ref(),
        }
    }
}

impl<R, I: AsyncIndexer> ZolanaClient<R, I> {
    /// The transfer proof of a transfer off the indexed route.
    async fn prove_transfer(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        match &self.prover {
            ProverBackend::Server(prover) => prover.prove_transfer(inputs).await,
            ProverBackend::Custom(prover) => {
                prove_on_blocking_pool(Arc::clone(prover), inputs).await
            }
        }
    }
}

/// A custom prover is synchronous and may run for seconds, so it proves on
/// Tokio's blocking pool rather than on the worker that awaits it.
async fn prove_on_blocking_pool(
    prover: Arc<dyn Prover>,
    inputs: &TransferInputs,
) -> Result<Proof, ClientError> {
    let request = crate::prover::requests::transfer(inputs)?;
    tokio::task::spawn_blocking(move || prover.prove(&request))
        .await
        .map_err(|error| ClientError::Prover(format!("prover task failed: {error}")))?
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
