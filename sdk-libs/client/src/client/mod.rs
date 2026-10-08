//! High-level Zolana client.
//!
//! [`ZolanaClient`] owns the three services a private transaction needs: the
//! Solana RPC, the indexer and the prover. The indexer fixes the client's mode:
//! over a [`ZolanaIndexer`], the default, the client blocks and implements
//! [`Rpc`](crate::rpc::Rpc); over an [`AsyncZolanaIndexer`] it is `async` and
//! implements [`AsyncRpc`](crate::rpc::AsyncRpc), and [`AsyncZolanaClient`]
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
        tee::{TeeError, TeePolicy},
        AsyncProverClient, Proof, Prover, ProverClient, TransferInputs,
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
/// `submit` proves through `TransferInputs`, and the widest confidential
/// transaction, 49x2 with every input real, consumes
/// 305,340 CU on a validator (`program-tests/spp-test-validator/tests/max_shapes.rs`).
/// The remaining headroom absorbs the per-input `create_nullifier_pdas` cost,
/// which moves with tree state rather than with the shape. The ring P256 rail
/// is more expensive again (356,230 CU at 49x2), but it carries its own
/// ceiling and does not come through here.
pub const DEFAULT_TRANSACT_CU_LIMIT: u32 = 450_000;

/// An indexer client a [`ZolanaClient`] is built over. It fixes the client's
/// mode, blocking for [`ZolanaIndexer`] and `async` for [`AsyncZolanaIndexer`],
/// and names the prover client of the same kind. Sealed.
pub trait Indexer: sealed::Sealed {
    type ProverClient;
}

impl Indexer for ZolanaIndexer {
    type ProverClient = ProverClient;
}

impl Indexer for AsyncZolanaIndexer {
    type ProverClient = AsyncProverClient;
}

mod sealed {
    use super::{
        AsyncProverClient, AsyncZolanaIndexer, Indexer, ProofDataSource, ProverClient, TeePolicy,
        ZolanaIndexer,
    };

    type ProverOf<I> = <I as Indexer>::ProverClient;

    /// What [`super::ZolanaClient`] does with its indexer and prover kind,
    /// out of the public API.
    pub trait Sealed: Sized {
        fn from_url(url: &str) -> Self;
        fn prover_client(url: String) -> ProverOf<Self>
        where
            Self: Indexer;
        fn proof_data_source(prover: &ProverOf<Self>) -> ProofDataSource
        where
            Self: Indexer;
        fn with_proof_data_source(
            prover: ProverOf<Self>,
            source: ProofDataSource,
        ) -> ProverOf<Self>
        where
            Self: Indexer;
        fn with_tee(prover: ProverOf<Self>, policy: TeePolicy) -> ProverOf<Self>
        where
            Self: Indexer;
    }

    impl Sealed for ZolanaIndexer {
        fn from_url(url: &str) -> Self {
            ZolanaIndexer::new(url)
        }

        fn prover_client(url: String) -> ProverClient {
            ProverClient::new(url)
        }

        fn proof_data_source(prover: &ProverClient) -> ProofDataSource {
            prover.proof_data_source()
        }

        fn with_proof_data_source(prover: ProverClient, source: ProofDataSource) -> ProverClient {
            prover.with_proof_data_source(source)
        }

        fn with_tee(prover: ProverClient, policy: TeePolicy) -> ProverClient {
            prover.with_tee(policy)
        }
    }

    impl Sealed for AsyncZolanaIndexer {
        fn from_url(url: &str) -> Self {
            AsyncZolanaIndexer::new(url)
        }

        fn prover_client(url: String) -> AsyncProverClient {
            AsyncProverClient::new(url)
        }

        fn proof_data_source(prover: &AsyncProverClient) -> ProofDataSource {
            prover.proof_data_source()
        }

        fn with_proof_data_source(
            prover: AsyncProverClient,
            source: ProofDataSource,
        ) -> AsyncProverClient {
            prover.with_proof_data_source(source)
        }

        fn with_tee(prover: AsyncProverClient, policy: TeePolicy) -> AsyncProverClient {
            prover.with_tee(policy)
        }
    }
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

    /// Build the indexer and prover clients from their URLs. Both must be
    /// https, or http to loopback: the indexer answers with the wallet's UTXO
    /// set and the prover is sent every proof input.
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
        Self::new(
            rpc,
            I::from_url(indexer_url.as_ref()),
            I::prover_client(prover_url.into()),
        )
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
                ProverBackend::Server(I::with_proof_data_source(prover, source))
            }
            custom => custom,
        };
        self
    }

    /// Send proofs only to a prover server that attests to `policy`; see
    /// [`ProverClient::with_tee`].
    ///
    /// Fails with [`TeeError::CustomProver`] on a client built by
    /// [`Self::with_prover`]: that prover is used as given, so a prover client
    /// passed there takes its policy from its own `with_tee`.
    pub fn with_prover_tee(self, policy: TeePolicy) -> Result<Self, ClientError> {
        let prover = match self.prover {
            ProverBackend::Server(prover) => ProverBackend::Server(I::with_tee(prover, policy)),
            ProverBackend::Custom(_) => return Err(TeeError::CustomProver.into()),
        };
        Ok(Self { prover, ..self })
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
                if I::proof_data_source(prover) == ProofDataSource::Prover =>
            {
                Some(prover)
            }
            _ => None,
        }
    }
}

impl<R> ZolanaClient<R, ZolanaIndexer> {
    /// The prover of a transfer off the indexed route.
    fn prover(&self) -> &dyn Prover {
        match &self.prover {
            ProverBackend::Server(prover) => prover,
            ProverBackend::Custom(prover) => prover.as_ref(),
        }
    }
}

impl<R> ZolanaClient<R, AsyncZolanaIndexer> {
    /// The transfer proof of a transfer off the indexed route.
    async fn prove_transfer(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        let prover = match &self.prover {
            ProverBackend::Server(prover) => return prover.prove_transfer(inputs).await,
            ProverBackend::Custom(prover) => Arc::clone(prover),
        };
        let request = crate::prover::requests::transfer(inputs)?;
        tokio::task::spawn_blocking(move || prover.prove(&request))
            .await
            .map_err(|error| ClientError::Prover(format!("prover task failed: {error}")))?
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
