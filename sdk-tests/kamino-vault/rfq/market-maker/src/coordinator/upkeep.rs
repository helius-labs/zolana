use solana_address::Address;
use tokio::sync::oneshot;
use zolana_interface::pda;

use super::{
    lifecycle::Retry, schedule::TransferStep, ConsolidateOrder, Coordinator, Operation,
    OperationOutcome, QueuedOperation,
};
use crate::{
    build::WithdrawalTarget,
    config::PairConfig,
    error::MakerError,
    rebalance::{RebalanceOrder, VaultFlow},
    scheduler::{
        payment::plan_consolidate,
        upkeep::{Upkeep, UpkeepPolicy},
    },
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
        for asset in self.assets.clone() {
            if self.ledger.tracker.unindexed(&asset) {
                continue;
            }
            let policy = UpkeepPolicy {
                profile: self.config.profile(&asset),
                max_inputs: self.budget.max_consolidate_inputs,
            };
            let Some(Upkeep { selection, parts }) =
                policy.plan(&self.ledger.tracker.available(&asset))
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

    pub(super) async fn check_ranges(&mut self) {
        if self.cancel.is_cancelled() || !self.queue.is_empty() || !self.steps.is_idle() {
            return;
        }
        for pair in self.config.pairs.clone() {
            let tracker = &self.ledger.tracker;
            if tracker.unindexed(&pair.vault.token_mint)
                || tracker.unindexed(&pair.vault.shares_mint)
            {
                continue;
            }
            match self.rebalance_need(&pair).await {
                Ok(Some(order)) => {
                    self.trigger_rebalance(order).await;
                    return;
                }
                Ok(None) => {}
                Err(error) => tracing::warn!(%error, "target range check failed"),
            }
        }
    }

    async fn rebalance_need(
        &self,
        pair: &PairConfig,
    ) -> Result<Option<RebalanceOrder>, MakerError> {
        let tracker = &self.ledger.tracker;
        let collateral = tracker.balance(&pair.vault.token_mint);
        let shares = tracker.balance(&pair.vault.shares_mint);
        let too_much_collateral = pair.collateral.range.filter(|range| collateral > range.max);
        let too_few_shares = pair.shares.range.filter(|range| shares < range.min);
        let too_little_collateral = pair.collateral.range.filter(|range| collateral < range.min);
        let too_many_shares = pair.shares.range.filter(|range| shares > range.max);
        let any = too_much_collateral.is_some()
            || too_few_shares.is_some()
            || too_little_collateral.is_some()
            || too_many_shares.is_some();
        if !any {
            return Ok(None);
        }
        let order = |flow, amount| RebalanceOrder {
            vault: pair.vault,
            flow,
            amount,
        };
        let state = order(VaultFlow::Deposit, 0)
            .vault_state(self.rpc.as_ref())
            .await?;
        let math = |error: anyhow::Error| MakerError::VaultMath {
            vault: pair.vault.vault,
            reason: error.to_string(),
        };
        let collateral_floor = pair.collateral.range.map_or(0, |range| range.min);
        let shares_floor = pair.shares.range.map_or(0, |range| range.min);
        let deposit = match (too_much_collateral, too_few_shares) {
            (Some(range), _) => Some(collateral - range.middle()),
            (None, Some(range)) => Some(
                state
                    .withdraw(range.middle() - shares)
                    .map_err(math)?
                    .tokens
                    .min(collateral.saturating_sub(collateral_floor)),
            ),
            (None, None) => None,
        };
        if let Some(amount) = deposit.filter(|amount| *amount > 0) {
            return Ok(Some(order(VaultFlow::Deposit, amount)));
        }
        let withdrawal = match (too_many_shares, too_little_collateral) {
            (Some(range), _) => Some(shares - range.middle()),
            (None, Some(range)) => Some(
                state
                    .deposit(range.middle() - collateral)
                    .map_err(math)?
                    .shares
                    .min(shares.saturating_sub(shares_floor)),
            ),
            (None, None) => None,
        };
        Ok(withdrawal
            .filter(|amount| *amount > 0)
            .map(|amount| order(VaultFlow::Withdrawal, amount)))
    }

    async fn trigger_rebalance(&mut self, order: RebalanceOrder) {
        let asset = match order.flow {
            VaultFlow::Deposit => order.vault.token_mint,
            VaultFlow::Withdrawal => order.vault.shares_mint,
        };
        if let Err(error) = self.ledger.queue(asset, order.amount) {
            tracing::warn!(%error, "automatic rebalance cannot be queued");
            return;
        }
        let (reply, outcome) = oneshot::channel();
        self.queue.push_back(QueuedOperation {
            id: self.ledger.next_operation(),
            operation: Operation::Consolidate(ConsolidateOrder {
                asset,
                withdrawal: order.amount,
                target: Some(WithdrawalTarget {
                    owner: self.payer,
                    token_program: pda::spl_token_program_id(),
                }),
                rebalance: Some(order),
            }),
            reply,
            attempts: 0,
        });
        let ledger = self.ledger.clone();
        self.tasks.spawn(async move {
            match outcome.await {
                Ok(Ok(OperationOutcome::Consolidated { receipt, .. })) => {
                    ledger.record_rebalance(receipt.signature);
                }
                Ok(Ok(OperationOutcome::Filled(_))) => {}
                Ok(Err(error)) => tracing::warn!(%error, "automatic rebalance failed"),
                Err(_) => {}
            }
        });
        self.try_schedule().await;
    }
}
