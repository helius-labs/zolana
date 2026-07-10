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
    material::{clone_keypair, load_sender_from_resolved_sync, WalletMaterial},
    resolve::resolve_sync_with_config,
    INDEXER_POLL, INDEXER_TIMEOUT,
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
    let sync = resolve_sync_with_config(opts, &config)?;
    let material = load_sender_from_resolved_sync(&sync)?;
    let indexer = ZolanaIndexer::new(sync.indexer_url.clone());
    let assets = config.local_asset_registry()?;
    let mut wallet = Wallet::new(clone_keypair(&material.keypair)?, assets)?;
    client_sync_wallet(&mut wallet, &indexer)?;
    Ok(SyncContext {
        material,
        wallet,
        local_assets: config.assets,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WaitOutcome {
    Indexed,
    ConfirmedPendingIndex,
}

impl WaitOutcome {
    pub(super) fn pending_suffix(self) -> &'static str {
        match self {
            Self::Indexed => "",
            Self::ConfirmedPendingIndex => " (indexing pending)",
        }
    }
}

pub(super) trait IndexProbe {
    fn is_indexed(&self, tree: Address, output_hash: [u8; 32]) -> Result<bool>;
}

pub(super) trait StatusProbe {
    fn classify(&self, signature: &Signature) -> Result<SignatureState>;
}

impl IndexProbe for ZolanaIndexer {
    fn is_indexed(&self, tree: Address, output_hash: [u8; 32]) -> Result<bool> {
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

pub(super) fn wait_for_indexed_output(
    indexer: &ZolanaIndexer,
    rpc: &SolanaRpc,
    tree: Pubkey,
    output_hash: [u8; 32],
    signature: Signature,
) -> Result<WaitOutcome> {
    wait_for_indexed_output_with(
        indexer,
        rpc,
        Address::new_from_array(tree.to_bytes()),
        output_hash,
        &signature,
        INDEXER_TIMEOUT,
        INDEXER_POLL,
        4,
    )
}

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
    let mut ticks = 0u32;
    loop {
        if index.is_indexed(tree, output_hash)? {
            return Ok(WaitOutcome::Indexed);
        }

        if status_check_every != 0 && ticks.is_multiple_of(status_check_every) {
            if let SignatureState::Failed(err) = status.classify(signature)? {
                bail!("transaction {signature} failed on-chain: {err}");
            }
        }

        if started.elapsed() >= timeout {
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
    use std::{cell::Cell, time::Duration};

    use super::*;

    struct MockIndex(bool);

    impl IndexProbe for MockIndex {
        fn is_indexed(&self, _tree: Address, _hash: [u8; 32]) -> Result<bool> {
            Ok(self.0)
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

    fn wait(indexed: bool, state: SignatureState, timeout: Duration) -> Result<WaitOutcome> {
        wait_for_indexed_output_with(
            &MockIndex(indexed),
            &MockStatus::new(state),
            Address::default(),
            [7u8; 32],
            &Signature::default(),
            timeout,
            Duration::from_millis(1),
            1,
        )
    }

    #[test]
    fn indexed_output_succeeds() {
        assert_eq!(
            wait(true, SignatureState::Confirmed, Duration::from_secs(1)).unwrap(),
            WaitOutcome::Indexed
        );
    }

    #[test]
    fn failed_transaction_errors_fast() {
        let err = wait(
            false,
            SignatureState::Failed("custom(1)".into()),
            Duration::from_secs(30),
        )
        .expect_err("failed transaction");
        assert!(err.to_string().contains("failed on-chain"));
    }

    #[test]
    fn confirmed_but_unindexed_is_success() {
        assert_eq!(
            wait(false, SignatureState::Confirmed, Duration::ZERO).unwrap(),
            WaitOutcome::ConfirmedPendingIndex
        );
    }

    #[test]
    fn pending_and_not_found_timeout_as_distinct_errors() {
        let pending =
            wait(false, SignatureState::Pending, Duration::ZERO).expect_err("pending transaction");
        assert!(pending.to_string().contains("processed on-chain"));

        let missing =
            wait(false, SignatureState::NotFound, Duration::ZERO).expect_err("missing transaction");
        assert!(missing.to_string().contains("not confirmed on-chain"));
    }
}
