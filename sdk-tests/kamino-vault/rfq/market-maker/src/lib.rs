mod build;
mod cache_pool;
mod chain;
mod config;
mod coordinator;
mod error;
mod ledger;
mod prove;
mod scheduler;
mod send;
mod step;
mod sync;
mod tracker;
mod watcher;

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, PoisonError,
    },
    time::Duration,
};

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_signature::Signature;
use solana_signer::Signer;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use zolana_client::{AsyncProverClient, AsyncRpc, AsyncSolanaRpc, AsyncZolanaIndexer};
use zolana_interface::pda;
use zolana_keypair::{ShieldedAddress, ShieldedKeypair};
use zolana_program_test::localnet::FixtureLocalnet;
use zolana_test_utils::wallet::Wallet;

use kamino_vault_rfq_sdk::{
    budget::{LegBudget, SwapBudget, USER_OUTPUTS},
    kvault::{self, token_balance, UserAccounts, VaultAccounts, VaultState},
    swap::{
        transact_data, Direction, Fill, Holdings, Offer, Quote, SwapError, SwapRequest,
        VaultOperation,
    },
    user::Receiver,
};

use self::{
    build::WithdrawalTarget,
    cache_pool::{AdoptedCache, CachePool, CachePoolConfig},
    chain::{blocking, send, shield_deposit},
    coordinator::{
        ConsolidateOrder, Coordinator, CoordinatorParts, Event, FillOrder, Operation,
        OperationOutcome, QueuedOperation,
    },
    ledger::Ledger,
    prove::{ProofQueue, ProofQueueConfig},
    send::SendQueue,
    sync::AccountSync,
    tracker::UtxoTracker,
    watcher::build_watcher,
};
pub use self::{
    config::{MakerConfig, WatcherConfig},
    coordinator::ConsolidateReceipt,
    error::MakerError,
    tracker::{CacheSlot, Lane},
};

pub struct MakerSetup {
    pub wallet: Wallet,
    pub keypair: ShieldedKeypair,
    pub config: MakerConfig,
    pub rpc_url: String,
    pub photon_url: String,
    pub tree: Address,
    pub assets: Vec<Address>,
}

#[derive(Clone)]
pub struct MarketMaker {
    inner: Arc<Inner>,
}

struct Inner {
    keypair: Arc<ShieldedKeypair>,
    identity: ShieldedAddress,
    fee_bps: AtomicU64,
    quote_ttl: Mutex<Duration>,
    budget: LegBudget,
    base_lanes: usize,
    ledger: Arc<Ledger>,
    account: Arc<tokio::sync::Mutex<AccountSync>>,
    events: mpsc::UnboundedSender<Event>,
    next_operation: AtomicU64,
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.cancel.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl MarketMaker {
    pub async fn start(setup: MakerSetup) -> Result<Self, MakerError> {
        let MakerSetup {
            wallet,
            keypair,
            config,
            rpc_url,
            photon_url,
            tree,
            assets,
        } = setup;
        let keypair = Arc::new(keypair);
        let identity = wallet.identity;
        let address = keypair.pubkey();
        let rpc: Arc<dyn AsyncRpc> = Arc::new(AsyncSolanaRpc::new(rpc_url));
        let indexer = Arc::new(AsyncZolanaIndexer::new(photon_url));
        let prover = Arc::new(AsyncProverClient::default());
        let tracker = Arc::new(UtxoTracker::default());
        let mut account = AccountSync::new(
            wallet,
            keypair.clone(),
            indexer.clone(),
            tracker.clone(),
            assets.clone(),
        );
        account.run_once().await?;

        let (pool, adopted) = CachePool::open(
            CachePoolConfig {
                rent_sponsor: address,
                write_authority: address,
                tree_id: config.tree_id,
                lifetime: config.cache_lifetime,
                rotation_margin: config.cache_rotation_margin,
            },
            rpc.as_ref(),
        )
        .await?;
        adopt_cache_slots(&tracker, &adopted);
        let swap_budget = SwapBudget::new(
            address,
            tree,
            pool.addresses().first().copied(),
            config.base_lanes,
        )?;
        let budget = swap_budget.leg_budget(config.maker_leg)?;

        let proofs = Arc::new(ProofQueue::new(ProofQueueConfig {
            authority: keypair.clone(),
            indexer,
            prover,
            base_workers: config.base_provers,
            max_workers: config.max_provers,
            payer: address,
            write_authority: address,
        }));
        let sender = Arc::new(SendQueue::new(rpc.clone(), keypair.clone()));
        let watcher = build_watcher(&config.watcher, rpc.clone());
        let ledger = Arc::new(Ledger::new(tracker));
        let account = Arc::new(tokio::sync::Mutex::new(account));
        let (events, receiver) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();

        let sync = spawn_sync(
            account.clone(),
            config.sync_interval,
            events.clone(),
            cancel.clone(),
        );
        let quote_ttl = config.quote_ttl;
        let base_lanes = config.base_lanes;
        let fee_bps = config.fee_bps;
        let coordinator = Coordinator::new(CoordinatorParts {
            config,
            assets,
            rpc,
            pool,
            watcher,
            ledger: ledger.clone(),
            keys: keypair.clone(),
            own: identity,
            payer: address,
            budget: swap_budget,
            proofs,
            sender,
            events: events.clone(),
            cancel: cancel.clone(),
        });
        let coordinator = tokio::spawn(coordinator.run(receiver));

        Ok(Self {
            inner: Arc::new(Inner {
                keypair,
                identity,
                fee_bps: AtomicU64::new(fee_bps),
                quote_ttl: Mutex::new(quote_ttl),
                budget,
                base_lanes,
                ledger,
                account,
                events,
                next_operation: AtomicU64::new(0),
                cancel,
                tasks: vec![sync, coordinator],
            }),
        })
    }

    pub fn identity(&self) -> ShieldedAddress {
        self.inner.identity
    }

    pub fn address(&self) -> Address {
        self.inner.keypair.pubkey()
    }

    pub fn budget(&self) -> LegBudget {
        self.inner.budget
    }

    pub fn set_fee_bps(&self, fee_bps: u64) {
        self.inner.fee_bps.store(fee_bps, Ordering::Relaxed);
    }

    pub fn set_quote_ttl(&self, ttl: Duration) {
        *self
            .inner
            .quote_ttl
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = ttl;
    }

    fn quote_ttl(&self) -> Duration {
        *self
            .inner
            .quote_ttl
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub fn holdings(&self, vault: &VaultAccounts) -> Holdings {
        let tracker = &self.inner.ledger.tracker;
        Holdings {
            usdc: tracker.balance(&vault.token_mint),
            shares: tracker.balance(&vault.shares_mint),
        }
    }

    pub fn lanes(&self, asset: &Address) -> Vec<Lane> {
        self.inner.ledger.tracker.lanes(asset)
    }

    pub async fn with_wallet<R>(&self, read: impl FnOnce(&Wallet, &ShieldedKeypair) -> R) -> R {
        let account = self.inner.account.lock().await;
        blocking(|| read(account.wallet(), &self.inner.keypair))
    }

    pub async fn sync(&self) -> Result<()> {
        self.inner.account.lock().await.run_once().await?;
        self.inner
            .events
            .send(Event::Synced)
            .map_err(|_| MakerError::CoordinatorStopped)?;
        Ok(())
    }

    pub async fn quote(
        &self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        direction: Direction,
        amount_in: u64,
    ) -> Result<Offer> {
        let rate = blocking(|| VaultState::read(localnet.client.rpc(), &vault.vault))?;
        Ok(Offer {
            quote: Quote::price(
                &rate,
                direction,
                amount_in,
                self.inner.fee_bps.load(Ordering::Relaxed),
            )?,
            maker: self.inner.identity,
            fee_payer: self.address(),
            max_user_inputs: self.inner.budget.max_user_inputs,
            user_outputs: USER_OUTPUTS,
        })
    }

    pub async fn fill(
        &self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        request: &SwapRequest,
    ) -> Result<Fill> {
        self.fill_to(localnet, vault, request, request.user).await
    }

    pub async fn fill_to(
        &self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        request: &SwapRequest,
        recipient: ShieldedAddress,
    ) -> Result<Fill> {
        let quote = request.quote;
        let (asset_in, asset_out) = quote.direction.assets(vault);
        self.check_user_leg(localnet, asset_in, request).await?;
        let outcome = self
            .operation(Operation::Fill(FillOrder {
                asset: asset_out,
                amount: quote.amount_out,
                recipient,
                user_leg: request.leg.clone(),
                ttl: self.quote_ttl(),
            }))
            .await
            .map_err(|error| match error {
                MakerError::InsufficientBalance {
                    asset,
                    available,
                    requested,
                } => anyhow::Error::from(SwapError::InsufficientInventory {
                    asset,
                    required: requested,
                    available,
                }),
                other => anyhow::Error::from(other),
            })?;
        match outcome {
            OperationOutcome::Filled(fill) => Ok(fill),
            OperationOutcome::Consolidated(_) => {
                Err(anyhow!("a fill operation returned a consolidation"))
            }
        }
    }

    async fn check_user_leg(
        &self,
        localnet: &FixtureLocalnet,
        asset_in: Address,
        request: &SwapRequest,
    ) -> Result<()> {
        let user_data = transact_data(&request.leg)?;
        if !user_data.interface_transfers.is_empty() {
            return Err(SwapError::PublicTransfer {
                count: user_data.interface_transfers.len(),
            }
            .into());
        }
        let max = self.inner.budget.max_user_inputs;
        if user_data.inputs.len() > max {
            return Err(SwapError::UserLegTooWide {
                inputs: user_data.inputs.len(),
                max,
            }
            .into());
        }
        if user_data.outputs.len() != USER_OUTPUTS {
            return Err(SwapError::UserLegOutputs {
                outputs: user_data.outputs.len(),
                expected: USER_OUTPUTS,
            }
            .into());
        }
        let received: u64 = self
            .with_wallet(|wallet, keypair| {
                Receiver {
                    keypair,
                    registry: &wallet.registry,
                    tree_id: localnet.tree_id,
                }
                .received(&user_data)
            })
            .await?
            .iter()
            .filter(|utxo| utxo.asset.asset == asset_in)
            .map(|utxo| utxo.amount)
            .sum();
        if received != request.quote.amount_in {
            return Err(SwapError::Underpaid {
                expected: request.quote.amount_in,
                received,
            }
            .into());
        }
        Ok(())
    }

    pub async fn settle(&self, fill: Fill, user_signature: Signature) -> Result<Signature> {
        let (reply, receipt) = oneshot::channel();
        self.inner
            .events
            .send(Event::Settle {
                step: fill.step,
                user_signature,
                reply,
            })
            .map_err(|_| MakerError::ShuttingDown)?;
        Ok(receipt
            .await
            .map_err(|_| MakerError::CoordinatorStopped)??)
    }

    pub async fn consolidate(&self, asset: Address) -> Result<ConsolidateReceipt> {
        self.consolidate_order(ConsolidateOrder {
            asset,
            withdrawal: 0,
            target: None,
        })
        .await
    }

    async fn consolidate_order(&self, order: ConsolidateOrder) -> Result<ConsolidateReceipt> {
        match self.operation(Operation::Consolidate(order)).await? {
            OperationOutcome::Consolidated(receipt) => Ok(receipt),
            OperationOutcome::Filled(_) => Err(anyhow!("a consolidate operation returned a fill")),
        }
    }

    async fn operation(&self, operation: Operation) -> Result<OperationOutcome, MakerError> {
        if self.inner.cancel.is_cancelled() {
            return Err(MakerError::ShuttingDown);
        }
        if matches!(&operation, Operation::Fill(order) if order.amount == 0) {
            return Err(MakerError::AmountZero);
        }
        let asset = operation.asset();
        let amount = operation.amount();
        self.inner.ledger.queue(asset, amount)?;
        let (reply, outcome) = oneshot::channel();
        let queued = QueuedOperation {
            id: self.inner.next_operation.fetch_add(1, Ordering::Relaxed),
            operation,
            reply,
            attempts: 0,
        };
        if self.inner.events.send(Event::Operation(queued)).is_err() {
            self.inner.ledger.unqueue(asset, amount);
            return Err(MakerError::ShuttingDown);
        }
        outcome.await.map_err(|_| MakerError::CoordinatorStopped)?
    }

    pub async fn shield(
        &self,
        localnet: &FixtureLocalnet,
        mint: Address,
        amount: u64,
    ) -> Result<Signature> {
        let signature = blocking(|| shield_deposit(localnet, &self.inner.keypair, mint, amount))?;
        self.sync().await?;
        Ok(signature)
    }

    pub async fn bootstrap(
        &self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        usdc: u64,
    ) -> Result<VaultOperation> {
        let operation = self.kvault_deposit(localnet, vault, usdc)?;
        self.shield_lanes(localnet, vault.shares_mint, operation.shares)
            .await?;
        Ok(operation)
    }

    async fn shield_lanes(
        &self,
        localnet: &FixtureLocalnet,
        mint: Address,
        amount: u64,
    ) -> Result<()> {
        let lanes = u64::try_from(self.inner.base_lanes.max(1))?;
        let part = amount / lanes;
        for lane in 0..lanes {
            let lane_amount = if lane + 1 == lanes {
                amount - part * (lanes - 1)
            } else {
                part
            };
            blocking(|| shield_deposit(localnet, &self.inner.keypair, mint, lane_amount))?;
        }
        self.sync().await
    }

    pub async fn rebalance_deposit(
        &self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        usdc: u64,
    ) -> Result<VaultOperation> {
        let unshield = self.unshield(vault.token_mint, usdc).await?;
        let operation = self.kvault_deposit(localnet, vault, usdc)?;
        self.shield_lanes(localnet, vault.shares_mint, operation.shares)
            .await?;
        Ok(VaultOperation {
            inputs: unshield.inputs,
            ..operation
        })
    }

    pub async fn rebalance_withdraw(
        &self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        shares: u64,
    ) -> Result<VaultOperation> {
        let unshield = self.unshield(vault.shares_mint, shares).await?;
        let operation = self.kvault_withdraw(localnet, vault, shares)?;
        self.shield(localnet, vault.token_mint, operation.tokens)
            .await?;
        Ok(VaultOperation {
            inputs: unshield.inputs,
            ..operation
        })
    }

    async fn unshield(&self, mint: Address, amount: u64) -> Result<ConsolidateReceipt> {
        self.sync().await?;
        self.consolidate_order(ConsolidateOrder {
            asset: mint,
            withdrawal: amount,
            target: Some(WithdrawalTarget {
                owner: self.address(),
                token_program: pda::spl_token_program_id(),
            }),
        })
        .await
    }

    fn public_accounts(&self, vault: &VaultAccounts) -> UserAccounts {
        let owner = self.address();
        UserAccounts {
            user: owner,
            token_account: pda::associated_token_address(&owner, &vault.token_mint),
            shares_account: pda::associated_token_address(&owner, &vault.shares_mint),
        }
    }

    fn kvault_operation(
        &self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        instruction: Instruction,
    ) -> Result<VaultOperation> {
        blocking(|| {
            let rpc = localnet.client.rpc();
            let accounts = self.public_accounts(vault);
            let before = VaultState::read(rpc, &vault.vault)?;
            let tokens_before = token_balance(rpc, &accounts.token_account)?;
            let shares_before = token_balance(rpc, &accounts.shares_account)?;
            send(
                rpc,
                &[instruction],
                self.inner.keypair.as_ref(),
                &[self.inner.keypair.as_ref()],
            )?;
            let tokens_after = token_balance(rpc, &accounts.token_account)?;
            let shares_after = token_balance(rpc, &accounts.shares_account)?;
            Ok(VaultOperation {
                before,
                after: VaultState::read(rpc, &vault.vault)?,
                tokens: tokens_before.abs_diff(tokens_after),
                shares: shares_before.abs_diff(shares_after),
                inputs: 0,
            })
        })
    }

    fn kvault_deposit(
        &self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        usdc: u64,
    ) -> Result<VaultOperation> {
        let accounts = self.public_accounts(vault);
        let ix = kvault::Deposit {
            vault,
            user: &accounts,
            max_amount: usdc,
        }
        .instruction();
        self.kvault_operation(localnet, vault, ix)
    }

    fn kvault_withdraw(
        &self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        shares: u64,
    ) -> Result<VaultOperation> {
        let accounts = self.public_accounts(vault);
        let ix = kvault::WithdrawFromAvailable {
            vault,
            user: &accounts,
            shares,
        }
        .instruction();
        self.kvault_operation(localnet, vault, ix)
    }
}

fn adopt_cache_slots(tracker: &UtxoTracker, adopted: &[AdoptedCache]) {
    for cache in adopted {
        for (index, hash) in cache.utxo_hashes.iter().enumerate() {
            let Ok(index) = u8::try_from(index) else {
                break;
            };
            if tracker.get(hash).is_some() {
                let slot = CacheSlot {
                    cache: cache.address,
                    index,
                };
                tracker.set_cache_slot(hash, Some(slot));
            }
        }
    }
}

fn spawn_sync(
    account: Arc<tokio::sync::Mutex<AccountSync>>,
    interval: Duration,
    events: mpsc::UnboundedSender<Event>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tick.tick() => match account.lock().await.run_once().await {
                    Ok(outcome) if outcome.changed() => {
                        let _ = events.send(Event::Synced);
                    }
                    Ok(_) => {}
                    Err(error) => tracing::warn!(%error, "sync failed"),
                },
            }
        }
    })
}
