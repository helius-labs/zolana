use std::collections::{HashSet, VecDeque};

use solana_address::Address;
use solana_instruction::Instruction;

use super::{ConsolidateOrder, Coordinator, FillOrder, Operation, QueuedOperation};
use kamino_vault_rfq_sdk::{budget::smallest_shape, kvault::VaultState};

use crate::{
    build::{TransferBuild, WithdrawalTarget},
    error::MakerError,
    rebalance::{MakerAccounts, RebalanceOrder, RebalanceTail, ShieldPlan},
    scheduler::{
        max_outputs_for,
        payment::{own_value, plan_consolidate, plan_payment, TransferPlan},
        select, select_all, Selection,
    },
    step::{FillLeg, OperationId, ProofWork, Step, StepId, StepKind},
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
    pub withdrawal: Option<WithdrawalTarget>,
    pub tail: Vec<Instruction>,
    pub vault_before: Option<VaultState>,
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
            match self.schedule(&queued).await {
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

    async fn schedule(&mut self, queued: &QueuedOperation) -> ScheduleOutcome {
        match &queued.operation {
            Operation::Fill(order) => self.schedule_fill(queued.id, order).await,
            Operation::Consolidate(order) => self.schedule_consolidate(queued.id, order).await,
        }
    }

    async fn schedule_fill(&mut self, id: OperationId, order: &FillOrder) -> ScheduleOutcome {
        let available = self.ledger.tracker.available(&order.asset);
        let max_inputs = match self.budget.max_maker_inputs(&order.user_leg) {
            Ok(max_inputs) => max_inputs,
            Err(error) => return ScheduleOutcome::Rejected(error.into()),
        };
        let Some(selection) = select(&available, order.amount, max_inputs) else {
            return self
                .unschedulable(order.asset, order.amount, max_inputs)
                .await;
        };
        let max_outputs = match self
            .budget
            .max_maker_outputs(&order.user_leg, selection.inputs.len())
        {
            Ok(max_outputs) => max_outputs,
            Err(error) => return ScheduleOutcome::Rejected(error.into()),
        };
        let change = match own_value(&selection, order.amount) {
            Ok(change) => change,
            Err(error) => return ScheduleOutcome::Rejected(error),
        };
        let change_parts = self.config.profile(&order.asset).parts(
            change,
            &self.other_lanes(&order.asset, &selection),
            max_outputs.saturating_sub(1),
        );
        let spends = selection
            .inputs
            .iter()
            .map(|input| input.utxo.wallet.nullifier)
            .collect();
        let plan = match plan_payment(selection, order.recipient, order.amount, change_parts) {
            Ok(plan) => plan,
            Err(error) => return ScheduleOutcome::Rejected(error),
        };
        let fill = FillLeg {
            user_leg: order.user_leg.clone(),
            ttl: order.ttl,
            spends,
            message: None,
            last_valid_block_height: 0,
            expires_at: None,
            transaction: None,
            settle: None,
        };
        let scheduled = self
            .schedule_transfer(TransferStep {
                kind: StepKind::Fill,
                asset: order.asset,
                operation: Some(id),
                plan,
                withdrawal: None,
                tail: Vec::new(),
                vault_before: None,
                fill: Some(fill),
            })
            .await;
        if let Ok(step) = scheduled {
            self.ledger
                .expect_fill(step, (order.asset, order.amount), order.inflow);
        }
        outcome(scheduled)
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
        let tail = match &order.rebalance {
            Some(rebalance) => match self.rebalance_tail(rebalance).await {
                Ok(tail) => Some(tail),
                Err(error) => return ScheduleOutcome::Rejected(error),
            },
            None => None,
        };
        let withdrawal = tail
            .as_ref()
            .map_or(order.withdrawal, |tail| tail.withdrawal);
        let instructions = tail
            .as_ref()
            .map(|tail| tail.instructions.clone())
            .unwrap_or_default();
        let accounts = order
            .target
            .filter(|_| tail.is_some())
            .map(|target| target.spl_accounts(order.asset));
        let max_inputs = match accounts {
            Some(accounts) => {
                match self
                    .budget
                    .max_consolidate_inputs_with(1, accounts, &instructions)
                {
                    Ok(max_inputs) => max_inputs,
                    Err(error) => return ScheduleOutcome::Rejected(error.into()),
                }
            }
            None => self.budget.max_consolidate_inputs,
        };
        let selection = select_all(&available, max_inputs);
        if selection.total < withdrawal || selection.inputs.is_empty() {
            if self.waits_for_lanes(&order.asset) {
                return ScheduleOutcome::Backlogged;
            }
            return ScheduleOutcome::Rejected(MakerError::InsufficientBalance {
                asset: order.asset,
                available: selection.total,
                requested: withdrawal,
            });
        }
        let inputs = selection.inputs.len();
        let kept = selection.total - withdrawal;
        let others = self.other_lanes(&order.asset, &selection);
        let profile = self.config.profile(&order.asset);
        let parts = (1..=max_outputs_for(inputs))
            .rev()
            .map(|max_parts| profile.parts(kept, &others, max_parts))
            .find(|parts| {
                let Some(accounts) = accounts else {
                    return true;
                };
                smallest_shape(inputs, parts.len().max(1)).is_some_and(|shape| {
                    self.budget
                        .consolidate_size(shape, accounts, &instructions)
                        .is_ok_and(|size| size.fits())
                })
            })
            .unwrap_or_else(|| profile.parts(kept, &others, 1));
        let plan = match plan_consolidate(selection, withdrawal, parts) {
            Ok(plan) => plan,
            Err(error) => return ScheduleOutcome::Rejected(error),
        };
        outcome(
            self.schedule_transfer(TransferStep {
                kind: StepKind::Consolidate,
                asset: order.asset,
                operation: Some(id),
                plan,
                withdrawal: order.target,
                tail: instructions,
                vault_before: tail.map(|tail| tail.before),
                fill: None,
            })
            .await,
        )
    }

    async fn rebalance_tail(&self, order: &RebalanceOrder) -> Result<RebalanceTail, MakerError> {
        let before = order.vault_state(self.rpc.as_ref()).await?;
        let shielded = order.shielded_asset();
        let shield = ShieldPlan {
            profile: self.config.profile(&shielded),
            lanes: self
                .ledger
                .tracker
                .lanes(&shielded)
                .into_iter()
                .map(|lane| lane.amount)
                .collect(),
            max_lanes: self.config.max_shield_lanes,
        };
        let maker = MakerAccounts {
            owner: self.payer,
            identity: self.own,
            tree: self.tree,
        };
        order.tail(before, maker, &shield, Vec::new())
    }

    pub(super) fn other_lanes(&self, asset: &Address, selection: &Selection) -> Vec<u64> {
        let selected = selection.hashes();
        self.ledger
            .tracker
            .lanes(asset)
            .into_iter()
            .filter(|lane| !selected.contains(&lane.utxo_hash))
            .map(|lane| lane.amount)
            .collect()
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
            withdrawal,
            tail,
            vault_before,
            fill,
        } = transfer;
        let inputs = plan.selection.hashes();
        let built = TransferBuild {
            plan,
            own: self.own,
            payer: self.payer,
            tree_id: self.config.tree_id,
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
        step.tail = tail;
        step.vault_before = vault_before;
        step.fill = fill;
        step.expected_outputs = built.expected_outputs;
        self.admit(step)?;
        Ok(id)
    }

    fn admit(&mut self, step: Step) -> Result<(), MakerError> {
        self.ledger.tracker.reserve(step.id, &step.inputs)?;
        if let Some(asset) = step.asset {
            let incoming = step
                .expected_outputs
                .iter()
                .map(|output| output.utxo.amount)
                .sum();
            self.ledger.expect(step.id, asset, incoming);
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
