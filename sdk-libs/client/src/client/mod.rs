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

use std::sync::{Arc, OnceLock};

use crate::{
    authority::ProofAuthority,
    error::ClientError,
    indexer::{AsyncZolanaIndexer, ZolanaIndexer},
    prover::{
        indexed::{PreparedIndexedTransfer, ProofDataSource, ProvenIndexedTransfer},
        tee::TeePolicy,
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
    /// Set by [`Self::with_prover`]; replaces both prover clients so no proof
    /// request reaches a prover server.
    custom_prover: Option<Arc<dyn Prover>>,
    blocking_indexer_url: Option<String>,
    blocking_prover_url: Option<String>,
    /// Applied to the blocking prover when it is built lazily.
    prover_tee: Option<TeePolicy>,
    async_indexer: AsyncZolanaIndexer,
    async_prover: AsyncProverClient,
    cu_limit: u32,
    priority_fee_lamports: Option<u64>,
    indexer_config: IndexerRpcConfig,
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
            custom_prover: None,
            blocking_indexer_url: None,
            blocking_prover_url: None,
            prover_tee: None,
            async_indexer,
            async_prover,
            cu_limit: DEFAULT_TRANSACT_CU_LIMIT,
            priority_fee_lamports: None,
            indexer_config: IndexerRpcConfig::default(),
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
            custom_prover: None,
            blocking_indexer_url: Some(indexer_url.clone()),
            blocking_prover_url: Some(prover_url.clone()),
            prover_tee: None,
            async_indexer: AsyncZolanaIndexer::new(indexer_url),
            async_prover: AsyncProverClient::new(prover_url),
            cu_limit: DEFAULT_TRANSACT_CU_LIMIT,
            priority_fee_lamports: None,
            indexer_config: IndexerRpcConfig::default(),
        }
    }

    /// Prove with `prover` instead of the prover server, for example on the
    /// device. Every proving method uses it, blocking and async alike, so the
    /// witness never leaves the process. The client fetches the proof data from
    /// the indexer itself, whatever [`Self::with_proof_data_source`] says. The
    /// async methods run the prover on Tokio's blocking pool.
    pub fn with_prover(mut self, prover: impl Prover + 'static) -> Self {
        self.custom_prover = Some(Arc::new(prover));
        self
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

    #[must_use]
    pub fn with_proof_data_source(mut self, source: ProofDataSource) -> Self {
        self.async_prover = self.async_prover.with_proof_data_source(source);
        if let Some(prover) = self.prover.take() {
            self.prover = OnceLock::from(prover.with_proof_data_source(source));
        }
        self
    }

    /// Applies [`ProverClient::with_tee`] to both prover clients.
    #[must_use]
    pub fn with_prover_tee(mut self, policy: TeePolicy) -> Self {
        self.async_prover = self.async_prover.with_tee(policy.clone());
        if let Some(prover) = self.prover.take() {
            self.prover = OnceLock::from(prover.with_tee(policy.clone()));
        }
        self.prover_tee = Some(policy);
        self
    }

    /// Whether a transfer takes the prover server's indexed route, where the
    /// server fetches the proof data. A custom prover only proves what the
    /// client hands it, so with one set the client always fetches the data
    /// itself and no transfer reaches the prover server.
    fn proves_indexed(&self) -> bool {
        self.custom_prover.is_none()
            && self.prover_client().proof_data_source() == ProofDataSource::Prover
    }

    fn proves_indexed_async(&self) -> bool {
        self.custom_prover.is_none()
            && self.async_prover.proof_data_source() == ProofDataSource::Prover
    }

    fn indexed_transfer(
        &self,
        preparation: TransferPreparation,
        authority: &dyn ProofAuthority,
    ) -> Result<ProvenIndexedTransfer, ClientError> {
        self.prover_client()
            .prove_indexed(&preparation.prepare(authority)?)
    }

    async fn indexed_transfer_async(
        &self,
        preparation: TransferPreparation,
        authority: &dyn ProofAuthority,
    ) -> Result<ProvenIndexedTransfer, ClientError> {
        self.async_prover
            .prove_indexed(&preparation.prepare(authority)?)
            .await
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

    fn blocking_prover(&self) -> &dyn Prover {
        match &self.custom_prover {
            Some(prover) => prover.as_ref(),
            None => self.prover_client(),
        }
    }

    fn prover_client(&self) -> &ProverClient {
        self.prover.get_or_init(|| {
            let prover = ProverClient::new(
                self.blocking_prover_url
                    .clone()
                    .expect("blocking prover URL is set when the client is deferred"),
            )
            .with_proof_data_source(self.async_prover.proof_data_source());
            match &self.prover_tee {
                Some(policy) => prover.with_tee(policy.clone()),
                None => prover,
            }
        })
    }

    /// The async counterpart of [`Self::blocking_prover`]'s transfer proof.
    async fn prove_transfer_async(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        let Some(prover) = &self.custom_prover else {
            return self.async_prover.prove_transfer(inputs).await;
        };
        let prover = Arc::clone(prover);
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
