use std::{
    thread::sleep,
    time::{Duration, Instant},
};

use anyhow::{bail, Result};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_client::{
    sync_wallet as client_sync_wallet, Rpc, SignatureState, SolanaRpc, ZolanaIndexer,
};
use zolana_transaction::{Address, Wallet};

use super::{
    indexer_timeout,
    material::{clone_keypair, load_sender_from_resolved_sync, WalletMaterial},
    resolve::resolve_sync_with_config,
    INDEXER_POLL,
};
use crate::{
    args::SyncOptions,
    cli_config::{CliConfigFile, LocalAssetConfig},
};

pub(super) struct SyncContext {
    pub(super) material: WalletMaterial,
    pub(super) wallet: Wallet,
    pub(super) local_assets: Vec<LocalAssetConfig>,
}

pub(super) fn sync_context(opts: &SyncOptions) -> Result<SyncContext> {
    let config = CliConfigFile::load()?;
    sync_context_with_config(opts, &config)
}

pub(super) fn sync_context_with_config(
    opts: &SyncOptions,
    config: &CliConfigFile,
) -> Result<SyncContext> {
    let sync = resolve_sync_with_config(opts, config)?;
    let material = load_sender_from_resolved_sync(&sync)?;
    let indexer = ZolanaIndexer::new(sync.indexer_url.clone());
    let assets = config.local_asset_registry()?;
    let mut wallet = Wallet::new(clone_keypair(&material.keypair)?, assets)?;
    client_sync_wallet(&mut wallet, &indexer)?;
    Ok(SyncContext {
        material,
        wallet,
        local_assets: config.assets.clone(),
    })
}

/// Outcome of waiting for a sent transaction to be indexed. Both variants mean
/// the transfer SUCCEEDED on-chain; they differ only in whether the indexer has
/// caught up. A caller reports success (exit 0) for either.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WaitOutcome {
    /// The output commitment is present in the indexer's tree.
    Indexed,
    /// The indexer has not caught up within the timeout, but the transaction is
    /// confirmed on-chain — a successful transfer whose indexing is pending.
    ConfirmedPendingIndex,
}

impl WaitOutcome {
    /// Suffix appended to the CLI success line for a confirmed-but-unindexed
    /// outcome.
    pub(super) fn pending_suffix(self) -> &'static str {
        match self {
            WaitOutcome::Indexed => "",
            WaitOutcome::ConfirmedPendingIndex => " (indexing pending)",
        }
    }
}

/// "Is this output committed to the tree yet?" probe. A returned merkle proof
/// for the leaf hash means the transaction is indexed.
pub(super) trait IndexProbe {
    fn is_indexed(&self, tree: Address, output_hash: [u8; 32]) -> Result<bool>;
}

/// On-chain signature classifier, so the wait can fail fast on a real failure
/// and treat confirmed-but-unindexed as success.
pub(super) trait StatusProbe {
    fn classify(&self, signature: &Signature) -> Result<SignatureState>;
}

impl IndexProbe for ZolanaIndexer {
    fn is_indexed(&self, tree: Address, output_hash: [u8; 32]) -> Result<bool> {
        // A leaf that is not yet indexed yields no proof (empty list or a
        // transient indexer error); either way it is "not indexed yet", so a
        // probe error is swallowed and retried rather than aborting the wait.
        match self.get_merkle_proofs(tree, vec![output_hash]) {
            Ok(response) => Ok(!response.proofs.is_empty()),
            Err(_) => Ok(false),
        }
    }
}

impl StatusProbe for SolanaRpc {
    fn classify(&self, signature: &Signature) -> Result<SignatureState> {
        Ok(self.signature_state(signature)?)
    }
}

/// Wait for `output_hash` to be indexed after sending `signature`, checking tx
/// status so a genuine failure aborts immediately and a confirmed-but-unindexed
/// transaction is reported as success on timeout.
///
/// Loop: if the output is indexed -> [`WaitOutcome::Indexed`]. Periodically check
/// on-chain status: a `Failed` transaction returns an error immediately (no full
/// wait). On timeout, a `Confirmed` transaction returns
/// [`WaitOutcome::ConfirmedPendingIndex`] (success); a `NotFound` transaction
/// errors (never confirmed). This is what stops the retry-flood: a landed
/// transfer never reports failure just because the indexer lags.
pub(super) fn wait_for_indexed_output(
    indexer: &ZolanaIndexer,
    rpc: &SolanaRpc,
    tree: Pubkey,
    output_hash: [u8; 32],
    signature: Signature,
) -> Result<WaitOutcome> {
    let tree = Address::new_from_array(tree.to_bytes());
    wait_for_indexed_output_with(
        indexer,
        rpc,
        tree,
        output_hash,
        &signature,
        indexer_timeout(),
        INDEXER_POLL,
        // Re-check tx status roughly every ~2s of polling (every 4th 500ms poll).
        4,
    )
}

/// Testable core of [`wait_for_indexed_output`], generic over the probes and with
/// explicit timing so a unit test can drive it with mocks and a short timeout.
#[allow(clippy::too_many_arguments)]
pub(super) fn wait_for_indexed_output_with<I: IndexProbe, S: StatusProbe>(
    index: &I,
    status: &S,
    tree: Address,
    output_hash: [u8; 32],
    signature: &Signature,
    timeout: Duration,
    poll: Duration,
    status_check_every: u32,
) -> Result<WaitOutcome> {
    let started = Instant::now();
    let mut ticks: u32 = 0;
    loop {
        if index.is_indexed(tree, output_hash)? {
            return Ok(WaitOutcome::Indexed);
        }

        // Fail fast on a genuine on-chain failure, without waiting out the whole
        // timeout. Checked periodically (not every poll) to keep RPC load down.
        if status_check_every != 0 && ticks.is_multiple_of(status_check_every) {
            if let SignatureState::Failed(err) = status.classify(signature)? {
                bail!("transaction {signature} failed on-chain: {err}");
            }
        }

        if started.elapsed() >= timeout {
            // Indexer lagged. A confirmed transaction is a successful transfer;
            // only a still-unseen signature is a real error.
            return match status.classify(signature)? {
                SignatureState::Failed(err) => {
                    bail!("transaction {signature} failed on-chain: {err}")
                }
                SignatureState::Confirmed => Ok(WaitOutcome::ConfirmedPendingIndex),
                SignatureState::Pending => bail!(
                    "timed out waiting for {signature}: processed on-chain but not confirmed and not indexed"
                ),
                SignatureState::NotFound => bail!(
                    "timed out waiting for {signature}: not indexed and not confirmed on-chain"
                ),
            };
        }
        ticks = ticks.wrapping_add(1);
        sleep(poll);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        time::{Duration, Instant},
    };

    use super::*;

    struct MockIndex {
        indexed: bool,
    }

    impl IndexProbe for MockIndex {
        fn is_indexed(&self, _tree: Address, _hash: [u8; 32]) -> Result<bool> {
            Ok(self.indexed)
        }
    }

    struct MockStatus {
        state: SignatureState,
        calls: Cell<usize>,
    }

    impl MockStatus {
        fn new(state: SignatureState) -> Self {
            Self {
                state,
                calls: Cell::new(0),
            }
        }
    }

    impl StatusProbe for MockStatus {
        fn classify(&self, _signature: &Signature) -> Result<SignatureState> {
            self.calls.set(self.calls.get() + 1);
            Ok(self.state.clone())
        }
    }

    fn wait(index: &MockIndex, status: &MockStatus, timeout: Duration) -> Result<WaitOutcome> {
        wait_for_indexed_output_with(
            index,
            status,
            Address::default(),
            [7u8; 32],
            &Signature::default(),
            timeout,
            Duration::from_millis(1),
            // Check status on the first poll (ticks % 1 == 0) so Failed aborts
            // without depending on multiple iterations.
            1,
        )
    }

    #[test]
    fn indexed_output_returns_indexed() {
        let index = MockIndex { indexed: true };
        let status = MockStatus::new(SignatureState::Confirmed);
        let outcome = wait(&index, &status, Duration::from_secs(5)).expect("indexed");
        assert_eq!(outcome, WaitOutcome::Indexed);
    }

    #[test]
    fn failed_transaction_errors_fast() {
        let index = MockIndex { indexed: false };
        let status = MockStatus::new(SignatureState::Failed("custom(1)".into()));
        // A generous timeout: the failure must be detected long before it elapses.
        let started = Instant::now();
        let err = wait(&index, &status, Duration::from_secs(30)).expect_err("failed tx must error");
        assert!(started.elapsed() < Duration::from_secs(5), "must fail fast");
        assert!(
            err.to_string().contains("failed on-chain"),
            "unexpected error: {err}"
        );
        assert!(status.calls.get() >= 1, "status must be checked");
    }

    #[test]
    fn timeout_with_confirmed_is_pending_index_success() {
        let index = MockIndex { indexed: false };
        let status = MockStatus::new(SignatureState::Confirmed);
        // Zero timeout: the first not-indexed check falls straight through to the
        // timeout branch, which reads Confirmed and reports success.
        let outcome =
            wait(&index, &status, Duration::from_millis(0)).expect("confirmed pending index");
        assert_eq!(outcome, WaitOutcome::ConfirmedPendingIndex);
    }

    #[test]
    fn timeout_with_not_found_errors() {
        let index = MockIndex { indexed: false };
        let status = MockStatus::new(SignatureState::NotFound);
        let err = wait(&index, &status, Duration::from_millis(0))
            .expect_err("not-found on timeout must error");
        assert!(
            err.to_string().contains("not confirmed on-chain"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn timeout_with_pending_errors() {
        let index = MockIndex { indexed: false };
        let status = MockStatus::new(SignatureState::Pending);
        let err = wait(&index, &status, Duration::from_millis(0))
            .expect_err("processed-but-unconfirmed on timeout must error");
        assert!(
            err.to_string()
                .contains("processed on-chain but not confirmed"),
            "unexpected error: {err}"
        );
    }
}
