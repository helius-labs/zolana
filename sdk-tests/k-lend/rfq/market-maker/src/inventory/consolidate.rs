use solana_address::Address;
use solana_signature::Signature;

use crate::{
    api::Inner,
    error::MakerError,
    inventory::balance::{
        profile::InventoryProfile,
        reservations::TrackedUtxo,
        select::{max_outputs_for, select_all, select_smallest, Selection},
    },
    transactions::{
        confirm::Retry,
        coordinator::{Coordinator, Operation, OperationOutcome, ScheduleOutcome},
        steps::{OperationId, StepId, StepKind},
        transfer::{plan_consolidate, TransferStep},
    },
};

pub struct ConsolidateOrder {
    pub asset: Address,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsolidateReceipt {
    pub signature: Signature,
    pub inputs: usize,
    pub outputs: usize,
}

pub struct Upkeep {
    pub selection: Selection,
    pub parts: Vec<u64>,
}

pub struct UpkeepPolicy<'a> {
    pub profile: &'a InventoryProfile,
    pub max_inputs: usize,
}

impl UpkeepPolicy<'_> {
    pub fn plan(&self, utxos: &[TrackedUtxo]) -> Option<Upkeep> {
        let utxos: Vec<TrackedUtxo> = utxos
            .iter()
            .filter(|utxo| utxo.amount() > 0)
            .cloned()
            .collect();
        let amounts: Vec<u64> = utxos.iter().map(TrackedUtxo::amount).collect();
        let balance: u64 = amounts.iter().sum();
        let surplus = self.profile.surplus_utxos(balance, &amounts);
        if surplus > 0 {
            return self.merge(&utxos, surplus);
        }
        if self.profile.missing(balance, &amounts).is_empty() {
            return None;
        }
        self.split(&utxos)
    }

    fn merge(&self, utxos: &[TrackedUtxo], surplus: usize) -> Option<Upkeep> {
        let selection = select_smallest(utxos, (surplus + 1).min(self.max_inputs));
        let inputs = selection.inputs.len();
        if inputs < 2 {
            return None;
        }
        let others = others(utxos, &selection);
        let max_parts = inputs.saturating_sub(surplus).min(max_outputs_for(inputs));
        let parts = self.profile.parts(selection.total, &others, max_parts);
        Some(Upkeep { selection, parts })
    }

    fn split(&self, utxos: &[TrackedUtxo]) -> Option<Upkeep> {
        let amounts: Vec<u64> = utxos.iter().map(TrackedUtxo::amount).collect();
        let (index, parts) = self.profile.split(&amounts, max_outputs_for(1))?;
        let selection = Selection::single(utxos.get(index)?)?;
        Some(Upkeep { selection, parts })
    }
}

fn others(utxos: &[TrackedUtxo], selection: &Selection) -> Vec<u64> {
    let selected = selection.hashes();
    utxos
        .iter()
        .filter(|utxo| !selected.contains(&utxo.utxo_hash()))
        .map(TrackedUtxo::amount)
        .collect()
}

impl Inner {
    pub async fn consolidate(&self, asset: Address) -> Result<ConsolidateReceipt, MakerError> {
        match self
            .operation(Operation::Consolidate(ConsolidateOrder { asset }))
            .await?
        {
            OperationOutcome::Consolidated(receipt) => Ok(receipt),
            _ => Err(MakerError::UnexpectedOutcome {
                expected: "consolidation",
            }),
        }
    }
}

impl Coordinator {
    pub async fn schedule_consolidate(
        &mut self,
        id: OperationId,
        order: &ConsolidateOrder,
    ) -> ScheduleOutcome {
        let available = self.services.pending.reservations.available(&order.asset);
        if available.len() < 2 {
            return ScheduleOutcome::Rejected(MakerError::NothingToConsolidate {
                asset: order.asset,
            });
        }
        let selection = select_all(&available, self.services.budget.max_consolidate_inputs);
        let inputs = selection.inputs.len();
        let others = self.other_utxos(&order.asset, &selection);
        let parts = self.config.profile(&order.asset).parts(
            selection.total,
            &others,
            max_outputs_for(inputs),
        );
        let plan = match plan_consolidate(selection, 0, parts) {
            Ok(plan) => plan,
            Err(error) => return ScheduleOutcome::Rejected(error),
        };
        self.schedule_transfer(TransferStep {
            kind: StepKind::Consolidate,
            asset: order.asset,
            operation: Some(id),
            plan,
            withdrawal: None,
            tail: Vec::new(),
            vault_before: None,
            fill: None,
        })
        .await
        .into()
    }

    pub async fn run_upkeep(&mut self) {
        let Some(idle_delay) = self.config.idle_delay else {
            return;
        };
        let idle = !self.runtime.cancel.is_cancelled()
            && self.queue.is_empty()
            && self.steps.is_idle()
            && self.last_operation.elapsed() >= idle_delay;
        if !idle {
            return;
        }
        for asset in self.config.assets() {
            if self.services.pending.reservations.unindexed(&asset) {
                continue;
            }
            let policy = UpkeepPolicy {
                profile: self.config.profile(&asset),
                max_inputs: self.services.budget.max_consolidate_inputs,
            };
            let Some(Upkeep { selection, parts }) =
                policy.plan(&self.services.pending.reservations.available(&asset))
            else {
                continue;
            };
            let scheduled = match plan_consolidate(selection, 0, parts) {
                Ok(plan) => {
                    self.schedule_transfer(TransferStep {
                        kind: StepKind::Consolidate,
                        asset,
                        operation: None,
                        plan,
                        withdrawal: None,
                        tail: Vec::new(),
                        vault_before: None,
                        fill: None,
                    })
                    .await
                }
                Err(error) => Err(error),
            };
            if let Err(error) = scheduled {
                tracing::warn!(%error, %asset, "upkeep consolidation could not be scheduled");
            }
        }
    }

    pub async fn preempt_upkeep(&mut self, asset: &Address) -> bool {
        let unsent: Vec<StepId> = self
            .steps
            .in_flight()
            .filter(|step| {
                step.is_upkeep() && step.state.is_unsent() && step.asset.as_ref() == Some(asset)
            })
            .map(|step| step.id)
            .collect();
        for id in &unsent {
            self.discard(*id, MakerError::Preempted, Retry::Requeue)
                .await;
        }
        !unsent.is_empty()
    }
}
