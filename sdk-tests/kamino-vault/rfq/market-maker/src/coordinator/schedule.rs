use std::collections::{HashSet, VecDeque};

use solana_address::Address;

use super::{ConsolidateOrder, Coordinator, FillOrder, Operation, QueuedOperation};
use kamino_vault_rfq_sdk::swap::Spend;

use crate::{
    build::{CacheWrites, PredictedUtxo, TransferBuild, WithdrawalTarget},
    error::MakerError,
    scheduler::{
        growth::Growth,
        payment::{plan_consolidate, plan_payment, TransferPlan},
        select, select_all,
        upkeep::UpkeepPolicy,
    },
    step::{FillLeg, OperationId, ProofWork, Step, StepId, StepKind},
    tracker::TrackedUtxo,
};

enum ScheduleOutcome {
    Scheduled,
    Backlogged,
    Retry,
    Rejected(MakerError),
}

pub(super) struct TransferStep {
    pub kind: StepKind,
    pub asset: Address,
    pub operation: Option<OperationId>,
    pub plan: TransferPlan,
    pub open_caches: bool,
    pub withdrawal: Option<WithdrawalTarget>,
    pub fill: Option<FillLeg>,
}

impl Coordinator {
    pub(super) async fn try_schedule(&mut self) {
        let mut pending: VecDeque<QueuedOperation> = std::mem::take(&mut self.queue);
        let mut blocked: HashSet<Address> = HashSet::new();
        let mut kept = VecDeque::new();
        while let Some(queued) = pending.pop_front() {
            let asset = queued.operation.asset();
            if blocked.contains(&asset) {
                kept.push_back(queued);
                continue;
            }
            let waiting = pending
                .iter()
                .chain(kept.iter())
                .filter(|other| is_fill_of(other, &asset))
                .count();
            match self.schedule(&queued, waiting).await {
                ScheduleOutcome::Scheduled => {
                    self.ledger.unqueue(asset, queued.operation.amount());
                    self.scheduled.insert(queued.id, queued);
                }
                ScheduleOutcome::Backlogged => {
                    blocked.insert(asset);
                    kept.push_back(queued);
                }
                ScheduleOutcome::Retry => pending.push_front(queued),
                ScheduleOutcome::Rejected(error) => {
                    self.ledger.unqueue(asset, queued.operation.amount());
                    let _ = queued.reply.send(Err(error));
                }
            }
        }
        let mut requeued = std::mem::take(&mut self.queue);
        requeued.append(&mut kept);
        self.queue = requeued;
    }

    async fn schedule(&mut self, queued: &QueuedOperation, waiting: usize) -> ScheduleOutcome {
        match &queued.operation {
            Operation::Fill(order) => self.schedule_fill(queued.id, order, waiting).await,
            Operation::Consolidate(order) => self.schedule_consolidate(queued.id, order).await,
        }
    }

    async fn schedule_fill(
        &mut self,
        id: OperationId,
        order: &FillOrder,
        waiting: usize,
    ) -> ScheduleOutcome {
        let available = self.ledger.tracker.available(&order.asset);
        let max_inputs = self.config.maker_leg.n_inputs();
        let Some(selection) = select(&available, order.amount, max_inputs) else {
            return self
                .unschedulable(order.asset, order.amount, max_inputs)
                .await;
        };
        let max_outputs = match self.budget.max_maker_outputs(
            &order.user_leg,
            selection.inputs.len(),
            self.config.maker_leg.n_outputs(),
        ) {
            Ok(max_outputs) => max_outputs,
            Err(error) => return ScheduleOutcome::Rejected(error.into()),
        };
        let change_outputs = Growth {
            queued: waiting,
            free_lanes: available.len().saturating_sub(selection.inputs.len()),
            tracked_lanes: self.ledger.tracker.lane_count(&order.asset),
            max_lanes: self.config.max_lanes,
            inputs: selection.inputs.len(),
            change: selection.total.saturating_sub(order.amount),
            min_lane_value: self.config.min_lane_value,
            max_outputs,
        }
        .change_outputs();
        let spends = selection
            .inputs
            .iter()
            .map(|input| Spend {
                nullifier: input.utxo.wallet.nullifier,
                cache_slot: input.cache_index(),
            })
            .collect();
        let plan = match plan_payment(selection, order.recipient, order.amount, change_outputs) {
            Ok(plan) => plan,
            Err(error) => return ScheduleOutcome::Rejected(error),
        };
        let fill = FillLeg {
            user_leg: order.user_leg.clone(),
            ttl: order.ttl,
            spends,
            change: Vec::new(),
            message: None,
            last_valid_block_height: 0,
            expires_at: None,
            transaction: None,
            settle: None,
        };
        outcome(
            self.schedule_transfer(TransferStep {
                kind: StepKind::Fill,
                asset: order.asset,
                operation: Some(id),
                plan,
                open_caches: false,
                withdrawal: None,
                fill: Some(fill),
            })
            .await,
        )
    }

    async fn schedule_consolidate(
        &mut self,
        id: OperationId,
        order: &ConsolidateOrder,
    ) -> ScheduleOutcome {
        let available = self.ledger.tracker.available(&order.asset);
        if order.withdrawal == 0 && available.len() < 2 {
            return ScheduleOutcome::Rejected(MakerError::NothingToConsolidate {
                asset: order.asset,
            });
        }
        let selection = select_all(&available, self.budget.max_consolidate_inputs);
        if selection.total < order.withdrawal || selection.inputs.is_empty() {
            if self.waits_for_lanes(&order.asset) {
                return ScheduleOutcome::Backlogged;
            }
            return ScheduleOutcome::Rejected(MakerError::InsufficientBalance {
                asset: order.asset,
                available: selection.total,
                requested: order.withdrawal,
            });
        }
        let parts = self
            .policy()
            .consolidate_parts(selection.total - order.withdrawal, selection.inputs.len());
        let plan = match plan_consolidate(selection, order.withdrawal, parts) {
            Ok(plan) => plan,
            Err(error) => return ScheduleOutcome::Rejected(error),
        };
        outcome(
            self.schedule_transfer(TransferStep {
                kind: StepKind::Consolidate,
                asset: order.asset,
                operation: Some(id),
                plan,
                open_caches: true,
                withdrawal: order.target,
                fill: None,
            })
            .await,
        )
    }

    pub(super) fn policy(&self) -> UpkeepPolicy {
        UpkeepPolicy {
            base_lanes: self.config.base_lanes,
            min_lane_value: self.config.min_lane_value,
        }
    }

    fn waits_for_lanes(&self, asset: &Address) -> bool {
        self.ledger.tracker.in_flight(asset) || self.ledger.tracker.unindexed(asset)
    }

    async fn unschedulable(
        &mut self,
        asset: Address,
        amount: u64,
        max_inputs: usize,
    ) -> ScheduleOutcome {
        if self.preempt_upkeep(&asset).await {
            return ScheduleOutcome::Retry;
        }
        if self.waits_for_lanes(&asset) {
            return ScheduleOutcome::Backlogged;
        }
        ScheduleOutcome::Rejected(MakerError::FragmentedInventory {
            asset,
            available: self.ledger.tracker.balance(&asset),
            requested: amount,
            max_inputs,
        })
    }

    pub(super) async fn schedule_transfer(
        &mut self,
        transfer: TransferStep,
    ) -> Result<StepId, MakerError> {
        let TransferStep {
            kind,
            asset,
            operation,
            plan,
            open_caches,
            withdrawal,
            fill,
        } = transfer;
        let writes = self
            .pool
            .allocate(
                &self.ledger.tracker,
                plan.own_output_count(&self.own),
                &plan.selection.cached_slots(),
                open_caches,
            )
            .map(|(cache, slots)| CacheWrites { cache, slots });
        self.publish_caches();
        let inputs = plan.selection.hashes();
        let read_cache = plan.selection.read_cache;
        let write_cache = writes.as_ref().map(|writes| writes.cache);
        let built = TransferBuild {
            plan,
            own: self.own,
            payer: self.payer,
            tree_id: self.config.tree_id,
            writes,
            withdrawal,
        }
        .run(self.keys.clone())
        .await?;
        let id = self.steps.next_id();
        let mut step = Step::new(
            id,
            kind,
            Some(ProofWork {
                inputs: built.proof_inputs,
                interface_accounts: built.interface_accounts,
            }),
        );
        step.asset = Some(asset);
        step.operation = operation;
        step.inputs = inputs;
        step.read_cache = read_cache;
        step.write_cache = write_cache;
        step.fill = fill.map(|mut fill| {
            fill.change = built
                .own_outputs
                .iter()
                .map(|output| output.wallet.clone())
                .collect();
            fill
        });
        self.admit(step, built.own_outputs)?;
        Ok(id)
    }

    fn admit(&mut self, mut step: Step, outputs: Vec<PredictedUtxo>) -> Result<(), MakerError> {
        self.ledger.tracker.reserve(step.id, &step.inputs)?;
        for predicted in outputs {
            step.own_outputs.push(predicted.wallet.utxo_hash);
            self.ledger.tracker.insert(TrackedUtxo {
                wallet: predicted.wallet,
                source: Some(step.id),
                leaf_index: None,
                cache_slot: predicted.cache_slot,
            });
        }
        let id = step.id;
        self.steps.insert(step);
        self.spawn_prove(id);
        Ok(())
    }
}

fn outcome(result: Result<StepId, MakerError>) -> ScheduleOutcome {
    match result {
        Ok(_) => ScheduleOutcome::Scheduled,
        Err(error) => ScheduleOutcome::Rejected(error),
    }
}

fn is_fill_of(queued: &QueuedOperation, asset: &Address) -> bool {
    matches!(&queued.operation, Operation::Fill(order) if order.asset == *asset)
}
