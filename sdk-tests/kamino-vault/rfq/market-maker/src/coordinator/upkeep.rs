use solana_address::Address;

use super::{lifecycle::Retry, schedule::TransferStep, Coordinator};
use crate::{
    error::MakerError,
    scheduler::{payment::plan_consolidate, upkeep::Upkeep},
    step::{StepId, StepKind},
};

impl Coordinator {
    pub(super) async fn run_upkeep(&mut self) {
        let Some(idle_delay) = self.config.idle_delay else {
            return;
        };
        let idle = !self.cancel.is_cancelled()
            && self.queue.is_empty()
            && self.steps.is_idle()
            && self.last_operation.elapsed() >= idle_delay;
        if !idle {
            return;
        }
        let policy = self.policy();
        for asset in self.assets.clone() {
            let Some(upkeep) = policy.plan(&self.ledger.tracker.available(&asset)) else {
                continue;
            };
            let (selection, parts) = match upkeep {
                Upkeep::Consolidate(selection) => (selection, 1),
                Upkeep::Split { selection, parts } => (selection, parts),
            };
            let scheduled = match plan_consolidate(selection, 0, parts) {
                Ok(plan) => {
                    self.schedule_transfer(TransferStep {
                        kind: StepKind::Consolidate,
                        asset,
                        operation: None,
                        plan,
                        open_caches: true,
                        withdrawal: None,
                        tail: Vec::new(),
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

    pub(super) async fn preempt_upkeep(&mut self, asset: &Address) -> bool {
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
