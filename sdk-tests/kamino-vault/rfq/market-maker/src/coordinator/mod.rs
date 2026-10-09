mod lifecycle;
mod schedule;
mod upkeep;

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use solana_address::Address;
use solana_instruction::Instruction;
use solana_signature::Signature;
use tokio::{
    sync::{mpsc, oneshot},
    time::MissedTickBehavior,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use zolana_client::AsyncRpc;
use zolana_keypair::{ShieldedAddress, ShieldedKeypair};

use kamino_vault_rfq_sdk::{budget::SwapBudget, kvault::VaultState, swap::Fill};

use super::{
    build::WithdrawalTarget,
    config::Settings,
    error::MakerError,
    ledger::{Inflow, Ledger},
    prove::ProofQueue,
    rebalance::RebalanceOrder,
    send::{SendOutcome, SendQueue},
    step::{OperationId, StepGraph, StepId},
};

pub struct FillOrder {
    pub asset: Address,
    pub amount: u64,
    pub recipient: ShieldedAddress,
    pub user_leg: Instruction,
    pub inflow: Inflow,
    pub ttl: Duration,
}

pub struct ConsolidateOrder {
    pub asset: Address,
    pub withdrawal: u64,
    pub target: Option<WithdrawalTarget>,
    pub rebalance: Option<RebalanceOrder>,
}

pub enum Operation {
    Fill(FillOrder),
    Consolidate(ConsolidateOrder),
}

impl Operation {
    pub fn asset(&self) -> Address {
        match self {
            Self::Fill(order) => order.asset,
            Self::Consolidate(order) => order.asset,
        }
    }

    pub fn amount(&self) -> u64 {
        match self {
            Self::Fill(order) => order.amount,
            Self::Consolidate(order) => order.withdrawal,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsolidateReceipt {
    pub signature: Signature,
    pub inputs: usize,
    pub outputs: usize,
}

pub enum OperationOutcome {
    Filled(Fill),
    Consolidated {
        receipt: ConsolidateReceipt,
        vault_before: Option<VaultState>,
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
        step: StepId,
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
}

pub struct CoordinatorParts {
    pub config: Settings,
    pub assets: Vec<Address>,
    pub rpc: Arc<dyn AsyncRpc>,
    pub ledger: Arc<Ledger>,
    pub keys: Arc<ShieldedKeypair>,
    pub own: ShieldedAddress,
    pub payer: Address,
    pub tree: Address,
    pub budget: Arc<SwapBudget>,
    pub proofs: Arc<ProofQueue>,
    pub sender: Arc<SendQueue>,
    pub events: mpsc::UnboundedSender<Event>,
    pub cancel: CancellationToken,
    pub tasks: TaskTracker,
}

pub struct Coordinator {
    config: Settings,
    assets: Vec<Address>,
    rpc: Arc<dyn AsyncRpc>,
    ledger: Arc<Ledger>,
    keys: Arc<ShieldedKeypair>,
    own: ShieldedAddress,
    payer: Address,
    tree: Address,
    budget: Arc<SwapBudget>,
    proofs: Arc<ProofQueue>,
    sender: Arc<SendQueue>,
    events: mpsc::UnboundedSender<Event>,
    cancel: CancellationToken,
    tasks: TaskTracker,
    steps: StepGraph,
    queue: VecDeque<QueuedOperation>,
    scheduled: HashMap<OperationId, QueuedOperation>,
    last_operation: Instant,
}

impl Coordinator {
    pub fn new(parts: CoordinatorParts) -> Self {
        Self {
            config: parts.config,
            assets: parts.assets,
            rpc: parts.rpc,
            ledger: parts.ledger,
            keys: parts.keys,
            own: parts.own,
            payer: parts.payer,
            tree: parts.tree,
            budget: parts.budget,
            proofs: parts.proofs,
            sender: parts.sender,
            events: parts.events,
            cancel: parts.cancel,
            tasks: parts.tasks,
            steps: StepGraph::default(),
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
                _ = self.cancel.cancelled() => break,
                event = events.recv() => match event {
                    Some(event) => self.handle(event).await,
                    None => break,
                },
                _ = status_tick.tick() => {
                    self.poll_statuses().await;
                    self.send_ready();
                    self.run_upkeep().await;
                    self.check_ranges().await;
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
                step,
                user_signature,
                reply,
            } => self.on_settle(step, user_signature, reply).await,
            Event::Expire(step) => self.on_expire(step).await,
            Event::Proven { step, result } => self.on_proven(step, result).await,
            Event::Sent { step, outcome } => self.on_sent(step, outcome).await,
            Event::Synced => self.try_schedule().await,
        }
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
        for (_, operation) in self.scheduled.drain() {
            let _ = operation.reply.send(Err(MakerError::ShuttingDown));
        }
    }

    fn reject_queued(&mut self) {
        for operation in self.queue.drain(..) {
            self.ledger
                .unqueue(operation.operation.asset(), operation.operation.amount());
            let _ = operation.reply.send(Err(MakerError::ShuttingDown));
        }
    }

    async fn drain_event(&mut self, event: Event) {
        match event {
            Event::Operation(operation) => {
                self.ledger
                    .unqueue(operation.operation.asset(), operation.operation.amount());
                let _ = operation.reply.send(Err(MakerError::ShuttingDown));
            }
            Event::Settle { reply, .. } => {
                let _ = reply.send(Err(MakerError::ShuttingDown));
            }
            Event::Sent { step, outcome } => self.on_sent(step, outcome).await,
            Event::Proven { .. } | Event::Expire(_) | Event::Synced => {}
        }
    }
}
