use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, RwLock},
    time::Instant,
};

use solana_address::Address;
use solana_instruction::Instruction;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use tokio::{
    sync::{mpsc, oneshot},
    time::MissedTickBehavior,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use zolana_client::{AsyncRpc, AsyncZolanaIndexer};

use k_lend_rfq_sdk::pair::VaultState;

use super::{
    budget::SwapBudget,
    prove::ProofQueue,
    send::{SendOutcome, SendQueue},
    steps::{OperationId, StepId, Steps},
};
use crate::{
    api::Inner,
    config::{ConfigUpdate, Settings},
    error::MakerError,
    inventory::balance::pending::{FillRanges, Outflow, PendingBalance},
    inventory::{
        consolidate::{ConsolidateOrder, ConsolidateReceipt},
        rebalance::RebalanceOrder,
    },
    swap::fill::{FillOrder, MakerFill},
    transactions::Identity,
};

pub enum Operation {
    Fill(FillOrder),
    Consolidate(ConsolidateOrder),
    Rebalance(RebalanceOrder),
}

impl Operation {
    pub fn asset(&self) -> Address {
        match self {
            Self::Fill(order) => order.asset,
            Self::Consolidate(order) => order.asset,
            Self::Rebalance(order) => order.spent_asset(),
        }
    }

    pub fn amount(&self) -> u64 {
        match self {
            Self::Fill(order) => order.amount,
            Self::Consolidate(_) => 0,
            Self::Rebalance(order) => order.amount,
        }
    }
}

pub enum OperationOutcome {
    Filled(MakerFill),
    Consolidated(ConsolidateReceipt),
    Rebalanced {
        receipt: ConsolidateReceipt,
        vault_before: VaultState,
    },
}

pub type OperationReply = oneshot::Sender<Result<OperationOutcome, MakerError>>;

pub struct QueuedOperation {
    pub id: OperationId,
    pub operation: Operation,
    pub reply: OperationReply,
    pub attempts: u32,
}

pub enum Event {
    Operation(QueuedOperation),
    Settle {
        message: VersionedMessage,
        user_signature: Signature,
        reply: oneshot::Sender<Result<Signature, MakerError>>,
    },
    Expire(StepId),
    Proven {
        step: StepId,
        result: Result<Instruction, MakerError>,
    },
    Sent {
        step: StepId,
        outcome: SendOutcome,
    },
    Synced,
    UpdateConfig {
        update: ConfigUpdate,
        reply: oneshot::Sender<Result<(), MakerError>>,
    },
}

pub enum ScheduleOutcome {
    Scheduled,
    Backlogged,
    Retry,
    Rejected(MakerError),
}

impl From<Result<StepId, MakerError>> for ScheduleOutcome {
    fn from(result: Result<StepId, MakerError>) -> Self {
        match result {
            Ok(_) => Self::Scheduled,
            Err(error) => Self::Rejected(error),
        }
    }
}

#[derive(Clone)]
pub struct Runtime {
    pub events: mpsc::UnboundedSender<Event>,
    pub cancel: CancellationToken,
    pub tasks: TaskTracker,
}

#[derive(Clone)]
pub struct Services {
    pub rpc: Arc<dyn AsyncRpc>,
    pub indexer: Arc<AsyncZolanaIndexer>,
    pub pending: Arc<PendingBalance>,
    pub budget: Arc<SwapBudget>,
    pub proofs: Arc<ProofQueue>,
    pub sender: Arc<SendQueue>,
}

pub struct Coordinator {
    pub config: Settings,
    pub shared_config: Arc<RwLock<Settings>>,
    pub identity: Identity,
    pub runtime: Runtime,
    pub services: Services,
    pub steps: Steps,
    pub queue: VecDeque<QueuedOperation>,
    pub scheduled: HashMap<OperationId, QueuedOperation>,
    pub last_operation: Instant,
}

impl Coordinator {
    pub fn new(
        config: Settings,
        shared_config: Arc<RwLock<Settings>>,
        identity: Identity,
        runtime: Runtime,
        services: Services,
    ) -> Self {
        Self {
            config,
            shared_config,
            identity,
            runtime,
            services,
            steps: Steps::default(),
            queue: VecDeque::new(),
            scheduled: HashMap::new(),
            last_operation: Instant::now(),
        }
    }

    pub async fn run(mut self, mut events: mpsc::UnboundedReceiver<Event>) {
        let mut status_tick = tokio::time::interval(self.config.status_interval);
        status_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = self.runtime.cancel.cancelled() => break,
                event = events.recv() => match event {
                    Some(event) => self.handle(event).await,
                    None => break,
                },
                _ = status_tick.tick() => {
                    self.poll_statuses().await;
                    self.send_ready();
                    self.run_upkeep().await;
                    self.check_ranges().await;
                    self.drop_retired();
                }
            }
        }
        self.drain(events).await;
    }

    async fn handle(&mut self, event: Event) {
        match event {
            Event::Operation(operation) => {
                self.last_operation = Instant::now();
                self.queue.push_back(operation);
                self.try_schedule().await;
            }
            Event::Settle {
                message,
                user_signature,
                reply,
            } => self.on_settle(&message, user_signature, reply).await,
            Event::Expire(step) => self.on_expire(step).await,
            Event::Proven { step, result } => self.on_proven(step, result).await,
            Event::Sent { step, outcome } => self.on_sent(step, outcome).await,
            Event::Synced => self.try_schedule().await,
            Event::UpdateConfig { update, reply } => self.on_update_config(update, reply).await,
        }
    }

    pub async fn try_schedule(&mut self) {
        let mut pending: VecDeque<QueuedOperation> = std::mem::take(&mut self.queue);
        let mut blocked: HashSet<Address> = HashSet::new();
        let mut kept = VecDeque::new();
        while let Some(queued) = pending.pop_front() {
            let asset = queued.operation.asset();
            if blocked.contains(&asset) {
                kept.push_back(queued);
                continue;
            }
            let outcome = match &queued.operation {
                Operation::Fill(order) => self.schedule_fill(queued.id, order).await,
                Operation::Consolidate(order) => self.schedule_consolidate(queued.id, order).await,
                Operation::Rebalance(order) => self.schedule_rebalance(queued.id, order).await,
            };
            match outcome {
                ScheduleOutcome::Scheduled => {
                    self.services
                        .pending
                        .unqueue(asset, queued.operation.amount());
                    self.scheduled.insert(queued.id, queued);
                }
                ScheduleOutcome::Backlogged => {
                    blocked.insert(asset);
                    kept.push_back(queued);
                }
                ScheduleOutcome::Retry => pending.push_front(queued),
                ScheduleOutcome::Rejected(error) => {
                    self.services
                        .pending
                        .unqueue(asset, queued.operation.amount());
                    self.fail(queued, error);
                }
            }
        }
        let mut requeued = std::mem::take(&mut self.queue);
        requeued.append(&mut kept);
        self.queue = requeued;
    }

    async fn drain(&mut self, mut events: mpsc::UnboundedReceiver<Event>) {
        self.reject_queued();
        let mut status_tick = tokio::time::interval(self.config.status_interval);
        while self.steps.has_pending_sends() {
            tokio::select! {
                Some(event) = events.recv() => self.drain_event(event).await,
                _ = status_tick.tick() => self.poll_statuses().await,
            }
        }
        events.close();
        while let Ok(event) = events.try_recv() {
            self.drain_event(event).await;
        }
        self.reject_queued();
        let scheduled: Vec<QueuedOperation> = self
            .scheduled
            .drain()
            .map(|(_, operation)| operation)
            .collect();
        for operation in scheduled {
            self.fail(operation, MakerError::ShuttingDown);
        }
    }

    fn reject_queued(&mut self) {
        let queued: Vec<QueuedOperation> = self.queue.drain(..).collect();
        for operation in queued {
            self.services
                .pending
                .unqueue(operation.operation.asset(), operation.operation.amount());
            self.fail(operation, MakerError::ShuttingDown);
        }
    }

    pub fn fail(&self, operation: QueuedOperation, error: MakerError) {
        self.services.pending.drop_fill(operation.id);
        let _ = operation.reply.send(Err(error));
    }

    async fn drain_event(&mut self, event: Event) {
        match event {
            Event::Operation(operation) => {
                self.services
                    .pending
                    .unqueue(operation.operation.asset(), operation.operation.amount());
                self.fail(operation, MakerError::ShuttingDown);
            }
            Event::Settle { reply, .. } => {
                let _ = reply.send(Err(MakerError::ShuttingDown));
            }
            Event::UpdateConfig { reply, .. } => {
                let _ = reply.send(Err(MakerError::ShuttingDown));
            }
            Event::Sent { step, outcome } => self.on_sent(step, outcome).await,
            Event::Proven { .. } | Event::Expire(_) | Event::Synced => {}
        }
    }
}

impl Inner {
    pub async fn operation(&self, operation: Operation) -> Result<OperationOutcome, MakerError> {
        if self.runtime.cancel.is_cancelled() {
            return Err(MakerError::ShuttingDown);
        }
        if matches!(&operation, Operation::Fill(order) if order.amount == 0) {
            return Err(MakerError::AmountZero);
        }
        let pending = &self.services.pending;
        let id = pending.next_operation();
        if let Operation::Fill(order) = &operation {
            pending.queue_fill(
                id,
                order.inflow,
                Outflow {
                    asset: order.asset,
                    amount: order.amount,
                },
                {
                    let settings = self.settings();
                    FillRanges {
                        inflow: settings.range(&order.inflow.asset),
                        outflow: settings.range(&order.asset),
                    }
                },
            )?;
        }
        let asset = operation.asset();
        let amount = operation.amount();
        if let Err(error) = pending.queue(asset, amount) {
            pending.drop_fill(id);
            return Err(error);
        }
        let (reply, outcome) = oneshot::channel();
        let queued = QueuedOperation {
            id,
            operation,
            reply,
            attempts: 0,
        };
        if self.runtime.events.send(Event::Operation(queued)).is_err() {
            pending.unqueue(asset, amount);
            pending.drop_fill(id);
            return Err(MakerError::ShuttingDown);
        }
        outcome.await.map_err(|_| MakerError::CoordinatorStopped)?
    }
}
