use solana_address::Address;
use solana_instruction::Instruction;
use solana_signature::Signature;
use tokio::sync::oneshot;
use zolana_interface::pda;

use k_lend_rfq_sdk::pair::{Pair, VaultState};

use crate::{
    api::{Inner, VaultOperation},
    config::PairConfig,
    error::MakerError,
    inventory::balance::select::{max_outputs_for, select_all},
    transactions::{
        budget::smallest_shape,
        confirm::confirm_indexed,
        coordinator::{Coordinator, Operation, OperationOutcome, QueuedOperation, ScheduleOutcome},
        kvault::{self, read_vault, UserAccounts},
        shield::ShieldPlan,
        steps::{OperationId, StepKind},
        transfer::{plan_consolidate, TransferStep, WithdrawalTarget},
        Identity,
    },
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RebalanceKind {
    Shares,
    Collateral,
}

#[derive(Clone, Copy, Debug)]
pub struct RebalanceOrder {
    pub pair: Pair,
    pub kind: RebalanceKind,
    pub amount: u64,
}

pub struct RebalanceTail {
    pub before: VaultState,
    pub withdrawal: u64,
    pub instructions: Vec<Instruction>,
}

impl RebalanceOrder {
    pub fn spent_asset(&self) -> Address {
        match self.kind {
            RebalanceKind::Shares => self.pair.token_mint,
            RebalanceKind::Collateral => self.pair.shares_mint,
        }
    }

    pub fn shielded_asset(&self) -> Address {
        match self.kind {
            RebalanceKind::Shares => self.pair.shares_mint,
            RebalanceKind::Collateral => self.pair.token_mint,
        }
    }

    pub fn tail(
        &self,
        before: VaultState,
        maker: &Identity,
        shield: &ShieldPlan,
        also_shield: Vec<(Address, u64)>,
    ) -> Result<RebalanceTail, MakerError> {
        let pair = &self.pair;
        let user = public_accounts(maker.payer, pair);
        let math = |error: anyhow::Error| MakerError::VaultMath {
            vault: pair.vault,
            reason: error.to_string(),
        };
        let (withdrawal, vault_instruction, shielded) = match self.kind {
            RebalanceKind::Shares => {
                let outcome = before.deposit(self.amount).map_err(math)?;
                let deposit = kvault::Deposit {
                    pair,
                    user: &user,
                    max_amount: outcome.tokens,
                }
                .instruction();
                (outcome.tokens, deposit, outcome.shares)
            }
            RebalanceKind::Collateral => {
                let outcome = before.withdraw(self.amount).map_err(math)?;
                let withdraw = kvault::WithdrawFromAvailable {
                    pair,
                    user: &user,
                    shares: outcome.shares,
                }
                .instruction();
                (outcome.shares, withdraw, outcome.tokens)
            }
        };
        let shielded_asset = self.shielded_asset();
        let shield = maker.shield(
            shield
                .amounts(shielded)
                .into_iter()
                .map(|amount| (shielded_asset, amount))
                .chain(also_shield)
                .collect(),
        )?;
        Ok(RebalanceTail {
            before,
            withdrawal,
            instructions: vec![vault_instruction, shield],
        })
    }
}

pub fn public_accounts(owner: Address, pair: &Pair) -> UserAccounts {
    UserAccounts {
        user: owner,
        token_account: pda::associated_token_address(&owner, &pair.token_mint),
        shares_account: pda::associated_token_address(&owner, &pair.shares_mint),
    }
}

impl Inner {
    pub async fn rebalance(
        &self,
        pair: &Pair,
        kind: RebalanceKind,
        amount: u64,
    ) -> Result<VaultOperation, MakerError> {
        self.sync().await?;
        let order = RebalanceOrder {
            pair: *pair,
            kind,
            amount,
        };
        match self.operation(Operation::Rebalance(order)).await? {
            OperationOutcome::Rebalanced {
                receipt,
                vault_before,
            } => {
                self.settled(pair, vault_before, receipt.signature, receipt.inputs)
                    .await
            }
            _ => Err(MakerError::UnexpectedOutcome {
                expected: "rebalance",
            }),
        }
    }

    pub async fn settled(
        &self,
        pair: &Pair,
        before: VaultState,
        signature: Signature,
        inputs: usize,
    ) -> Result<VaultOperation, MakerError> {
        confirm_indexed(&self.services, signature).await?;
        self.sync().await?;
        let after = read_vault(self.services.rpc.as_ref(), pair.vault).await?;
        Ok(VaultOperation {
            before,
            after,
            tokens: before.token_available.abs_diff(after.token_available),
            shares: before.shares_issued.abs_diff(after.shares_issued),
            inputs,
            signature,
        })
    }
}

impl Coordinator {
    pub async fn schedule_rebalance(
        &mut self,
        id: OperationId,
        order: &RebalanceOrder,
    ) -> ScheduleOutcome {
        let asset = order.spent_asset();
        let tail = match self.rebalance_tail(order).await {
            Ok(tail) => tail,
            Err(error) => return ScheduleOutcome::Rejected(error),
        };
        let target = WithdrawalTarget {
            owner: self.identity.payer,
            token_program: pda::spl_token_program_id(),
        };
        let accounts = target.spl_accounts(asset);
        let budget = self.services.budget.clone();
        let max_inputs = match budget.max_consolidate_inputs_with(1, accounts, &tail.instructions) {
            Ok(max_inputs) => max_inputs,
            Err(error) => return ScheduleOutcome::Rejected(error.into()),
        };
        let available = self.services.pending.reservations.available(&asset);
        let selection = select_all(&available, max_inputs);
        if selection.total < tail.withdrawal || selection.inputs.is_empty() {
            if self.waits_for_utxos(&asset) {
                return ScheduleOutcome::Backlogged;
            }
            return ScheduleOutcome::Rejected(MakerError::InsufficientBalance {
                asset,
                available: selection.total,
                requested: tail.withdrawal,
            });
        }
        let inputs = selection.inputs.len();
        let kept = selection.total - tail.withdrawal;
        let others = self.other_utxos(&asset, &selection);
        let profile = self.config.profile(&asset);
        let parts = (1..=max_outputs_for(inputs))
            .rev()
            .map(|max_parts| profile.parts(kept, &others, max_parts))
            .find(|parts| {
                smallest_shape(inputs, parts.len().max(1)).is_some_and(|shape| {
                    budget
                        .consolidate_size(shape, accounts, &tail.instructions)
                        .is_ok_and(|size| size.fits())
                })
            })
            .unwrap_or_else(|| profile.parts(kept, &others, 1));
        let plan = match plan_consolidate(selection, tail.withdrawal, parts) {
            Ok(plan) => plan,
            Err(error) => return ScheduleOutcome::Rejected(error),
        };
        self.schedule_transfer(TransferStep {
            kind: StepKind::Rebalance,
            asset,
            operation: Some(id),
            plan,
            withdrawal: Some(target),
            tail: tail.instructions,
            vault_before: Some(tail.before),
            fill: None,
        })
        .await
        .into()
    }

    async fn rebalance_tail(&self, order: &RebalanceOrder) -> Result<RebalanceTail, MakerError> {
        let before = read_vault(self.services.rpc.as_ref(), order.pair.vault).await?;
        let shield = ShieldPlan::new(
            &self.config,
            &self.services.pending.reservations,
            &order.shielded_asset(),
        );
        order.tail(before, &self.identity, &shield, Vec::new())
    }

    pub async fn check_ranges(&mut self) {
        if self.runtime.cancel.is_cancelled() || !self.queue.is_empty() || !self.steps.is_idle() {
            return;
        }
        for config in self.config.pairs.clone() {
            if self.config.retiring.contains(&config.pair.vault) {
                continue;
            }
            let reservations = &self.services.pending.reservations;
            if reservations.unindexed(&config.pair.token_mint)
                || reservations.unindexed(&config.pair.shares_mint)
            {
                continue;
            }
            match self.rebalance_need(&config).await {
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
        config: &PairConfig,
    ) -> Result<Option<RebalanceOrder>, MakerError> {
        let reservations = &self.services.pending.reservations;
        let collateral = reservations.balance(&config.pair.token_mint);
        let shares = reservations.balance(&config.pair.shares_mint);
        let too_much_collateral = config
            .collateral
            .range
            .filter(|range| collateral > range.max);
        let too_few_shares = config.shares.range.filter(|range| shares < range.min);
        let too_little_collateral = config
            .collateral
            .range
            .filter(|range| collateral < range.min);
        let too_many_shares = config.shares.range.filter(|range| shares > range.max);
        let any = too_much_collateral.is_some()
            || too_few_shares.is_some()
            || too_little_collateral.is_some()
            || too_many_shares.is_some();
        if !any {
            return Ok(None);
        }
        let order = |kind, amount| RebalanceOrder {
            pair: config.pair,
            kind,
            amount,
        };
        let state = read_vault(self.services.rpc.as_ref(), config.pair.vault).await?;
        let math = |error: anyhow::Error| MakerError::VaultMath {
            vault: config.pair.vault,
            reason: error.to_string(),
        };
        let collateral_floor = config.collateral.range.map_or(0, |range| range.min);
        let shares_floor = config.shares.range.map_or(0, |range| range.min);
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
            return Ok(Some(order(RebalanceKind::Shares, amount)));
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
            .map(|amount| order(RebalanceKind::Collateral, amount)))
    }

    async fn trigger_rebalance(&mut self, order: RebalanceOrder) {
        let asset = order.spent_asset();
        if let Err(error) = self.services.pending.queue(asset, order.amount) {
            tracing::warn!(%error, "automatic rebalance cannot be queued");
            return;
        }
        let (reply, outcome) = oneshot::channel();
        self.queue.push_back(QueuedOperation {
            id: self.services.pending.next_operation(),
            operation: Operation::Rebalance(order),
            reply,
            attempts: 0,
        });
        let pending = self.services.pending.clone();
        self.runtime.tasks.spawn(async move {
            match outcome.await {
                Ok(Ok(OperationOutcome::Rebalanced { receipt, .. })) => {
                    pending.record_rebalance(receipt.signature);
                }
                Ok(Ok(_)) => {}
                Ok(Err(error)) => tracing::warn!(%error, "automatic rebalance failed"),
                Err(_) => {}
            }
        });
        self.try_schedule().await;
    }
}
