use std::sync::Arc;

use solana_address::Address;
use zolana_client::AsyncZolanaIndexer;
use zolana_keypair::ShieldedKeypair;
use zolana_test_utils::wallet::{sync_wallet_async, Wallet};

use super::{
    error::MakerError,
    tracker::{TrackedUtxo, UtxoTracker},
};

pub struct AccountSync {
    wallet: Wallet,
    keypair: Arc<ShieldedKeypair>,
    indexer: Arc<AsyncZolanaIndexer>,
    tracker: Arc<UtxoTracker>,
    assets: Vec<Address>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncOutcome {
    pub inserted: usize,
    pub removed: usize,
}

impl SyncOutcome {
    pub fn changed(&self) -> bool {
        self.inserted > 0 || self.removed > 0
    }
}

impl AccountSync {
    pub fn new(
        wallet: Wallet,
        keypair: Arc<ShieldedKeypair>,
        indexer: Arc<AsyncZolanaIndexer>,
        tracker: Arc<UtxoTracker>,
        assets: Vec<Address>,
    ) -> Self {
        Self {
            wallet,
            keypair,
            indexer,
            tracker,
            assets,
        }
    }

    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }

    pub async fn run_once(&mut self) -> Result<SyncOutcome, MakerError> {
        sync_wallet_async(
            &mut self.wallet,
            self.keypair.as_ref(),
            self.indexer.as_ref(),
        )
        .await
        .map_err(MakerError::Sync)?;
        let mut inserted = 0;
        for asset in &self.assets {
            for utxo in self.wallet.balance(*asset, None)?.utxos {
                if utxo.utxo.amount == 0 {
                    continue;
                }
                let tracked = TrackedUtxo {
                    leaf_index: Some(utxo.leaf_index),
                    wallet: utxo,
                    source: None,
                    cache_slot: None,
                };
                if self.tracker.insert(tracked) {
                    inserted += 1;
                }
            }
        }
        let spent = &self.wallet.nullifiers;
        let removed = self
            .tracker
            .remove_spent_nullifiers(|nullifier| spent.contains(nullifier));
        Ok(SyncOutcome { inserted, removed })
    }
}
