use std::sync::{Arc, Mutex, PoisonError, RwLock, RwLockReadGuard};

use anyhow::Result;
use solana_address::Address;
use solana_signature::Signature;
use solana_signer::Signer;
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use zolana_client::{AsyncProverClient, AsyncRpc, AsyncSolanaRpc, AsyncZolanaIndexer};
use zolana_keypair::{ShieldedAddress, ShieldedKeypair};
use zolana_transaction::{AssetRegistry, WalletUtxo};

use k_lend_rfq_sdk::{
    pair::{Pair, VaultState},
    swap::{Direction, Fill, Offer, SwapRequest},
};

use crate::{
    config::{ConfigUpdate, IdentityConfig, MarketMakerConfig, Settings},
    error::MakerError,
    inventory::balance::{
        pending::PendingBalance,
        reservations::{InventoryUtxo, Reservations},
        sync::asset_registry,
        sync::{spawn_sync, AccountSync},
    },
    inventory::{consolidate::ConsolidateReceipt, rebalance::RebalanceKind},
    swap::fill::MakerFill,
    transactions::{
        budget::{BudgetError, SwapBudget, USER_OUTPUTS},
        coordinator::{Coordinator, Runtime, Services},
        prove::{ProofQueue, ProofQueueConfig},
        send::SendQueue,
        Identity,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Holdings {
    pub collateral: u64,
    pub shares: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultOperation {
    pub before: VaultState,
    pub after: VaultState,
    pub tokens: u64,
    pub shares: u64,
    pub inputs: usize,
    pub signature: Signature,
}

#[derive(Clone)]
pub struct MarketMaker {
    inner: Arc<Inner>,
}

pub struct Inner {
    pub identity: Identity,
    pub runtime: Runtime,
    pub services: Services,
    pub config: Arc<RwLock<Settings>>,
    pub max_user_inputs: usize,
    pub max_maker_inputs: usize,
    pub registry: Arc<RwLock<AssetRegistry>>,
    pub account: Arc<tokio::sync::Mutex<AccountSync>>,
    background: Mutex<Vec<JoinHandle<()>>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.runtime.cancel.cancel();
        self.runtime.tasks.close();
        for task in self
            .background
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            task.abort();
        }
    }
}

impl Inner {
    pub fn settings(&self) -> RwLockReadGuard<'_, Settings> {
        self.config.read().unwrap_or_else(PoisonError::into_inner)
    }
}

impl MarketMaker {
    pub async fn start(config: MarketMakerConfig) -> Result<Self, MakerError> {
        let MarketMakerConfig {
            connection,
            identity: IdentityConfig { keypair },
            pairs,
            concurrency,
            quotes,
        } = config;
        let config = Settings::new(&concurrency, quotes, pairs);
        let keys = Arc::new(keypair);
        let identity = Identity {
            own: keys.shielded_address()?,
            payer: keys.pubkey(),
            keys,
            tree: connection.tree,
            tree_id: connection.tree_id,
        };
        let rpc: Arc<dyn AsyncRpc> = Arc::new(AsyncSolanaRpc::new(connection.rpc_url));
        let indexer = Arc::new(AsyncZolanaIndexer::new(connection.photon_url));
        let prover = Arc::new(
            connection
                .prover_url
                .map_or_else(AsyncProverClient::default, AsyncProverClient::new),
        );
        let registry = Arc::new(RwLock::new(
            asset_registry(rpc.as_ref(), config.assets()).await?,
        ));
        let reservations = Arc::new(Reservations::default());
        let mut account = AccountSync::new(
            identity.keys.clone(),
            indexer.clone(),
            reservations.clone(),
            registry.clone(),
        )?;
        account.run_once().await?;

        let budget = Arc::new(SwapBudget::new(identity.payer, identity.tree, 1)?);
        let max_user_inputs = budget.max_user_inputs(budget.narrowest_maker()?)?.ok_or(
            BudgetError::NoSupportedShape {
                inputs: 1,
                outputs: USER_OUTPUTS,
            },
        )?;
        let max_maker_inputs = budget.max_maker_inputs(&budget.narrowest_user_transfer()?)?;

        let proofs = Arc::new(ProofQueue::new(ProofQueueConfig {
            authority: identity.keys.clone(),
            indexer: indexer.clone(),
            prover,
            base_workers: concurrency.provers,
            max_workers: concurrency.max_provers,
            payer: identity.payer,
        }));
        let sender = Arc::new(SendQueue::new(rpc.clone(), identity.keys.clone()));
        let services = Services {
            rpc,
            indexer,
            pending: Arc::new(PendingBalance::new(reservations)),
            budget,
            proofs,
            sender,
        };
        let account = Arc::new(tokio::sync::Mutex::new(account));
        let (events, receiver) = mpsc::unbounded_channel();
        let runtime = Runtime {
            events,
            cancel: CancellationToken::new(),
            tasks: TaskTracker::new(),
        };

        let sync = spawn_sync(
            account.clone(),
            concurrency.sync_interval,
            runtime.events.clone(),
            runtime.cancel.clone(),
        );
        let shared_config = Arc::new(RwLock::new(config.clone()));
        let coordinator = Coordinator::new(
            config,
            shared_config.clone(),
            identity.clone(),
            runtime.clone(),
            services.clone(),
        );
        let coordinator = tokio::spawn(coordinator.run(receiver));

        Ok(Self {
            inner: Arc::new(Inner {
                identity,
                runtime,
                services,
                config: shared_config,
                max_user_inputs,
                max_maker_inputs,
                registry,
                account,
                background: Mutex::new(vec![sync, coordinator]),
            }),
        })
    }

    pub async fn update_config(&self, update: ConfigUpdate) -> Result<()> {
        Ok(self.inner.update_config(update).await?)
    }

    pub async fn shutdown(&self) {
        self.inner.runtime.cancel.cancel();
        let background = std::mem::take(
            &mut *self
                .inner
                .background
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        for task in background {
            if let Err(error) = task.await {
                tracing::warn!(%error, "background task ended abnormally");
            }
        }
        self.inner.runtime.tasks.close();
        self.inner.runtime.tasks.wait().await;
    }

    pub fn rebalances(&self) -> Vec<Signature> {
        self.inner.services.pending.rebalances()
    }

    pub fn identity(&self) -> ShieldedAddress {
        self.inner.identity.own
    }

    pub fn address(&self) -> Address {
        self.inner.identity.payer
    }

    pub fn keypair(&self) -> &ShieldedKeypair {
        &self.inner.identity.keys
    }

    pub fn max_user_inputs(&self) -> usize {
        self.inner.max_user_inputs
    }

    pub fn holdings(&self, pair: &Pair) -> Holdings {
        let reservations = &self.inner.services.pending.reservations;
        Holdings {
            collateral: reservations.balance(&pair.token_mint),
            shares: reservations.balance(&pair.shares_mint),
        }
    }

    pub fn utxos(&self, asset: &Address) -> Vec<InventoryUtxo> {
        self.inner.services.pending.reservations.utxos(asset)
    }

    pub fn spendable(&self, asset: &Address) -> Vec<WalletUtxo> {
        self.inner.services.pending.reservations.spendable(asset)
    }

    pub async fn sync(&self) -> Result<()> {
        Ok(self.inner.sync().await?)
    }

    pub async fn quote(&self, pair: &Pair, direction: Direction, amount_in: u64) -> Result<Offer> {
        self.inner.quote(pair, direction, amount_in).await
    }

    pub async fn fill(&self, pair: &Pair, request: &SwapRequest) -> Result<MakerFill> {
        self.inner.fill(pair, request).await
    }

    pub async fn settle(&self, fill: &Fill, user_signature: Signature) -> Result<Signature> {
        Ok(self.inner.settle(fill, user_signature).await?)
    }

    pub async fn consolidate(&self, asset: Address) -> Result<ConsolidateReceipt> {
        Ok(self.inner.consolidate(asset).await?)
    }

    pub async fn seed_inventory(
        &self,
        pair: &Pair,
        deposit: u64,
        collateral: u64,
    ) -> Result<VaultOperation> {
        Ok(self.inner.seed_inventory(pair, deposit, collateral).await?)
    }

    pub async fn rebalance_shares(&self, pair: &Pair, collateral: u64) -> Result<VaultOperation> {
        Ok(self
            .inner
            .rebalance(pair, RebalanceKind::Shares, collateral)
            .await?)
    }

    pub async fn rebalance_collateral(&self, pair: &Pair, shares: u64) -> Result<VaultOperation> {
        Ok(self
            .inner
            .rebalance(pair, RebalanceKind::Collateral, shares)
            .await?)
    }
}
