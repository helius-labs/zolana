mod build;
mod chain;
mod config;
mod coordinator;
mod error;
mod ledger;
mod prove;
mod rebalance;
mod scheduler;
mod send;
mod step;
mod sync;
mod tracker;

use std::{
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_signature::Signature;
use solana_signer::Signer;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use zolana_client::{
    transaction_size, AsyncProverClient, AsyncRpc, AsyncSolanaRpc, AsyncZolanaIndexer,
};
use zolana_interface::pda;
use zolana_keypair::{ShieldedAddress, ShieldedKeypair};
use zolana_program_test::localnet::FixtureLocalnet;
use zolana_test_utils::wallet::Wallet;

use kamino_vault_rfq_sdk::{
    budget::{smallest_shape, BudgetError, SwapBudget, MAKER_MIN_OUTPUTS, USER_OUTPUTS},
    kvault::{Pair, VaultState},
    rebalance::REBALANCE_COMPUTE_BUDGET,
    swap::{
        transact_data, Direction, Fill, Holdings, Offer, Quote, SwapError, SwapRequest,
        VaultOperation,
    },
    user::Receiver,
};

use self::{
    build::WithdrawalTarget,
    chain::{blocking, send, shield_deposit},
    config::Settings,
    coordinator::{
        ConsolidateOrder, Coordinator, CoordinatorParts, Event, FillOrder, Operation,
        OperationOutcome, QueuedOperation,
    },
    ledger::{Inflow, Ledger},
    prove::{ProofQueue, ProofQueueConfig},
    rebalance::{MakerAccounts, RebalanceKind, RebalanceOrder, ShieldPlan},
    scheduler::width,
    send::SendQueue,
    sync::AccountSync,
    tracker::UtxoTracker,
};
pub use self::{
    config::{
        ConcurrencyConfig, ConnectionConfig, IdentityConfig, MarketMakerConfig, PairConfig,
        QuoteConfig, TargetRange, TokenConfig,
    },
    coordinator::ConsolidateReceipt,
    error::MakerError,
    scheduler::profile::LaneProfile,
    tracker::Lane,
};

#[derive(Clone)]
pub struct MarketMaker {
    inner: Arc<Inner>,
}

struct Inner {
    keypair: Arc<ShieldedKeypair>,
    identity: ShieldedAddress,
    quotes: QuoteConfig,
    budget: Arc<SwapBudget>,
    max_user_inputs: usize,
    max_maker_inputs: usize,
    config: Settings,
    tree: Address,
    ledger: Arc<Ledger>,
    account: Arc<tokio::sync::Mutex<AccountSync>>,
    events: mpsc::UnboundedSender<Event>,
    cancel: CancellationToken,
    background: Mutex<Vec<JoinHandle<()>>>,
    tasks: TaskTracker,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.tasks.close();
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

impl MarketMaker {
    pub async fn start(config: MarketMakerConfig) -> Result<Self, MakerError> {
        let MarketMakerConfig {
            connection,
            identity: IdentityConfig { keypair, wallet },
            pairs,
            concurrency,
            quotes,
        } = config;
        let config = Settings::new(&connection, &concurrency, pairs);
        let assets = config.assets();
        let tree = connection.tree;
        let rpc_url = connection.rpc_url;
        let photon_url = connection.photon_url;
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

        let budget = Arc::new(SwapBudget::new(address, tree, 1)?);
        let max_user_inputs = budget.max_user_inputs(budget.narrowest_maker()?)?.ok_or(
            BudgetError::NoSupportedShape {
                inputs: 1,
                outputs: USER_OUTPUTS,
            },
        )?;
        let max_maker_inputs = budget.max_maker_inputs(&budget.narrowest_user_transfer()?)?;

        let proofs = Arc::new(ProofQueue::new(ProofQueueConfig {
            authority: keypair.clone(),
            indexer,
            prover,
            base_workers: concurrency.provers,
            max_workers: concurrency.max_provers,
            payer: address,
        }));
        let sender = Arc::new(SendQueue::new(rpc.clone(), keypair.clone()));
        let ledger = Arc::new(Ledger::new(tracker));
        let account = Arc::new(tokio::sync::Mutex::new(account));
        let (events, receiver) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();
        let tasks = TaskTracker::new();

        let sync = spawn_sync(
            account.clone(),
            concurrency.sync_interval,
            events.clone(),
            cancel.clone(),
        );
        let maker_config = config.clone();
        let coordinator = Coordinator::new(CoordinatorParts {
            config,
            assets,
            rpc,
            ledger: ledger.clone(),
            keys: keypair.clone(),
            own: identity,
            payer: address,
            tree,
            budget: budget.clone(),
            proofs,
            sender,
            events: events.clone(),
            cancel: cancel.clone(),
            tasks: tasks.clone(),
        });
        let coordinator = tokio::spawn(coordinator.run(receiver));

        Ok(Self {
            inner: Arc::new(Inner {
                keypair,
                identity,
                quotes,
                budget,
                max_user_inputs,
                max_maker_inputs,
                config: maker_config,
                tree,
                ledger,
                account,
                events,
                cancel,
                background: Mutex::new(vec![sync, coordinator]),
                tasks,
            }),
        })
    }

    pub async fn shutdown(&self) {
        self.inner.cancel.cancel();
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
        self.inner.tasks.close();
        self.inner.tasks.wait().await;
    }

    pub fn rebalances(&self) -> Vec<Signature> {
        self.inner.ledger.rebalances()
    }

    pub fn identity(&self) -> ShieldedAddress {
        self.inner.identity
    }

    pub fn address(&self) -> Address {
        self.inner.keypair.pubkey()
    }

    pub fn max_user_inputs(&self) -> usize {
        self.inner.max_user_inputs
    }

    pub fn holdings(&self, pair: &Pair) -> Holdings {
        let tracker = &self.inner.ledger.tracker;
        Holdings {
            collateral: tracker.balance(&pair.token_mint),
            shares: tracker.balance(&pair.shares_mint),
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
        pair: &Pair,
        direction: Direction,
        amount_in: u64,
    ) -> Result<Offer> {
        let rate = blocking(|| VaultState::read(localnet.client.rpc(), &pair.vault))?;
        let quote = Quote::price(&rate, direction, amount_in, self.inner.quotes.fee_bps)?;
        let (asset_in, asset_out) = direction.assets(pair);
        self.check_range(asset_out, quote.amount_out, false)?;
        self.check_range(asset_in, amount_in, true)?;
        Ok(Offer {
            quote,
            maker: self.inner.identity,
            fee_payer: self.address(),
            max_user_inputs: self.quoted_user_inputs(asset_out, quote.amount_out)?,
            user_outputs: USER_OUTPUTS,
        })
    }

    fn check_range(&self, asset: Address, amount: u64, incoming: bool) -> Result<(), SwapError> {
        let Some(range) = self.inner.config.range(&asset) else {
            return Ok(());
        };
        let balance = self.inner.ledger.net_balance(&asset);
        let balance_after = if incoming {
            balance.saturating_add(amount)
        } else {
            balance.saturating_sub(amount)
        };
        let outside = if incoming {
            balance_after > range.max
        } else {
            balance_after < range.min
        };
        if outside {
            return Err(SwapError::OutsideTargetRange {
                asset,
                balance_after,
                min: range.min,
                max: range.max,
            });
        }
        Ok(())
    }

    fn quoted_user_inputs(&self, asset: Address, amount: u64) -> Result<usize> {
        let lanes: Vec<u64> = self.lanes(&asset).iter().map(|lane| lane.amount).collect();
        let available: u64 = lanes.iter().sum();
        let max_inputs = self.inner.max_maker_inputs;
        let too_wide = SwapError::MakerTransferTooWide {
            asset,
            required: amount,
            max_inputs,
        };
        let Some(inputs) = width(lanes, amount, max_inputs) else {
            if available < amount {
                return Err(SwapError::InsufficientInventory {
                    asset,
                    required: amount,
                    available,
                }
                .into());
            }
            return Err(too_wide.into());
        };
        let maker =
            smallest_shape(inputs, MAKER_MIN_OUTPUTS).ok_or(SwapError::NoSupportedShape {
                inputs,
                outputs: MAKER_MIN_OUTPUTS,
            })?;
        Ok(self.inner.budget.max_user_inputs(maker)?.ok_or(too_wide)?)
    }

    pub async fn fill(
        &self,
        localnet: &FixtureLocalnet,
        pair: &Pair,
        request: &SwapRequest,
    ) -> Result<Fill> {
        let quote = request.quote;
        let (asset_in, asset_out) = quote.direction.assets(pair);
        let inflow = self
            .check_user_transfer(localnet, asset_in, request)
            .await?;
        let outcome = self
            .operation(Operation::Fill(FillOrder {
                asset: asset_out,
                amount: quote.amount_out,
                recipient: request.user,
                user_transfer: request.transfer.clone(),
                inflow,
                ttl: self.inner.quotes.ttl,
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
            OperationOutcome::Consolidated { .. } => {
                Err(anyhow!("a fill operation returned a consolidation"))
            }
        }
    }

    async fn check_user_transfer(
        &self,
        localnet: &FixtureLocalnet,
        asset_in: Address,
        request: &SwapRequest,
    ) -> Result<Inflow> {
        let user_data = transact_data(&request.transfer)?;
        if !user_data.interface_transfers.is_empty() {
            return Err(SwapError::PublicTransfer {
                count: user_data.interface_transfers.len(),
            }
            .into());
        }
        let max = self.inner.max_user_inputs;
        if user_data.inputs.len() > max {
            return Err(SwapError::UserTransferTooWide {
                inputs: user_data.inputs.len(),
                max,
            }
            .into());
        }
        if user_data.outputs.len() != USER_OUTPUTS {
            return Err(SwapError::UserTransferOutputs {
                outputs: user_data.outputs.len(),
                expected: USER_OUTPUTS,
            }
            .into());
        }
        let outputs: Vec<_> = self
            .with_wallet(|wallet, keypair| {
                Receiver {
                    keypair,
                    registry: &wallet.registry,
                    tree_id: localnet.tree_id,
                }
                .received_outputs(&user_data)
            })
            .await?
            .into_iter()
            .filter(|(utxo, _)| utxo.asset.asset == asset_in)
            .collect();
        let received: u64 = outputs.iter().map(|(utxo, _)| utxo.amount).sum();
        if received != request.quote.amount_in {
            return Err(SwapError::Underpaid {
                expected: request.quote.amount_in,
                received,
            }
            .into());
        }
        let utxo_hash = outputs
            .first()
            .map(|(_, hash)| *hash)
            .ok_or(SwapError::Underpaid {
                expected: request.quote.amount_in,
                received,
            })?;
        Ok(Inflow {
            asset: asset_in,
            amount: received,
            utxo_hash,
        })
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
        let (receipt, _) = self
            .consolidate_order(ConsolidateOrder {
                asset,
                withdrawal: 0,
                target: None,
                rebalance: None,
            })
            .await?;
        Ok(receipt)
    }

    async fn consolidate_order(
        &self,
        order: ConsolidateOrder,
    ) -> Result<(ConsolidateReceipt, Option<VaultState>)> {
        match self.operation(Operation::Consolidate(order)).await? {
            OperationOutcome::Consolidated {
                receipt,
                vault_before,
            } => Ok((receipt, vault_before)),
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
            id: self.inner.ledger.next_operation(),
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

    pub async fn seed_inventory(
        &self,
        localnet: &FixtureLocalnet,
        pair: &Pair,
        deposit: u64,
        collateral: u64,
    ) -> Result<VaultOperation> {
        let rpc = localnet.client.rpc();
        let before = blocking(|| VaultState::read(rpc, &pair.vault))?;
        let order = RebalanceOrder {
            pair: *pair,
            kind: RebalanceKind::Shares,
            amount: deposit,
        };
        let collateral_lanes = self
            .shield_plan(&pair.token_mint)
            .amounts(collateral)
            .into_iter()
            .map(|amount| (pair.token_mint, amount))
            .collect();
        let tail = order.tail(
            before,
            self.maker_accounts(),
            &self.shield_plan(&order.shielded_asset()),
            collateral_lanes,
        )?;
        let size = transaction_size(
            &self.address(),
            &tail.instructions,
            REBALANCE_COMPUTE_BUDGET,
        )?;
        if !size.fits() {
            return Err(MakerError::TransactionTooLarge {
                bytes: size.bytes,
                addresses: size.addresses,
            }
            .into());
        }
        let keypair = self.inner.keypair.as_ref();
        let signature = blocking(|| send(rpc, &tail.instructions, keypair, &[keypair]))?;
        self.settled(localnet, pair, before, signature, 0).await
    }

    pub async fn rebalance_shares(
        &self,
        localnet: &FixtureLocalnet,
        pair: &Pair,
        collateral: u64,
    ) -> Result<VaultOperation> {
        self.rebalance(localnet, pair, RebalanceKind::Shares, collateral)
            .await
    }

    pub async fn rebalance_collateral(
        &self,
        localnet: &FixtureLocalnet,
        pair: &Pair,
        shares: u64,
    ) -> Result<VaultOperation> {
        self.rebalance(localnet, pair, RebalanceKind::Collateral, shares)
            .await
    }

    async fn rebalance(
        &self,
        localnet: &FixtureLocalnet,
        pair: &Pair,
        kind: RebalanceKind,
        amount: u64,
    ) -> Result<VaultOperation> {
        self.sync().await?;
        let asset = match kind {
            RebalanceKind::Shares => pair.token_mint,
            RebalanceKind::Collateral => pair.shares_mint,
        };
        let (receipt, before) = self
            .consolidate_order(ConsolidateOrder {
                asset,
                withdrawal: amount,
                target: Some(WithdrawalTarget {
                    owner: self.address(),
                    token_program: pda::spl_token_program_id(),
                }),
                rebalance: Some(RebalanceOrder {
                    pair: *pair,
                    kind,
                    amount,
                }),
            })
            .await?;
        let before = before.ok_or_else(|| anyhow!("a rebalance returned no vault state"))?;
        self.settled(localnet, pair, before, receipt.signature, receipt.inputs)
            .await
    }

    async fn settled(
        &self,
        localnet: &FixtureLocalnet,
        pair: &Pair,
        before: VaultState,
        signature: Signature,
        inputs: usize,
    ) -> Result<VaultOperation> {
        blocking(|| localnet.client.confirm_private_transaction_sync(signature))
            .map_err(|e| anyhow!("index vault operation {signature}: {e:?}"))?;
        self.sync().await?;
        let after = blocking(|| VaultState::read(localnet.client.rpc(), &pair.vault))?;
        Ok(VaultOperation {
            before,
            after,
            tokens: before.token_available.abs_diff(after.token_available),
            shares: before.shares_issued.abs_diff(after.shares_issued),
            inputs,
            signature,
        })
    }

    fn maker_accounts(&self) -> MakerAccounts {
        MakerAccounts {
            owner: self.address(),
            identity: self.inner.identity,
            tree: self.inner.tree,
        }
    }

    fn shield_plan(&self, asset: &Address) -> ShieldPlan<'_> {
        ShieldPlan {
            profile: self.inner.config.profile(asset),
            lanes: self.lanes(asset).iter().map(|lane| lane.amount).collect(),
            max_lanes: self.inner.config.max_shield_lanes,
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
