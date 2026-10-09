use std::time::Duration;

use solana_address::Address;
use solana_signature::Signature;
use zolana_client::{AsyncRpc, IndexerPollConfig};
use zolana_interface::{error::ShieldedPoolError, pda};

use super::{
    coordinator::{Coordinator, OperationOutcome, Services},
    prove::PROVE_ATTEMPTS,
    send::{classify, Sent, StepStatus},
    steps::{StepId, StepKind, StepState},
};
use crate::{
    error::MakerError, inventory::balance::reservations::TrackedUtxo,
    inventory::consolidate::ConsolidateReceipt,
};

const OPERATION_ATTEMPTS: u32 = 3;
const SEND_ATTEMPTS: usize = 5;
const REPROVE_CODES: [u32; 2] = [
    ShieldedPoolError::TransactProofVerificationFailed as u32,
    ShieldedPoolError::StaleNullifierRoot as u32,
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    Requeue,
    Fail,
}

impl Coordinator {
    pub async fn poll_statuses(&mut self) {
        let sent: Vec<(StepId, Vec<Sent>)> = self
            .steps
            .sent()
            .map(|step| (step.id, step.sends.clone()))
            .collect();
        if sent.is_empty() {
            return;
        }
        let signatures: Vec<Signature> = sent
            .iter()
            .flat_map(|(_, sends)| sends.iter().map(|sent| sent.signature))
            .collect();
        let (statuses, block_height) = match futures::try_join!(
            self.services.sender.statuses(&signatures),
            self.services.sender.block_height()
        ) {
            Ok(polled) => polled,
            Err(error) => {
                tracing::warn!(%error, "status poll failed");
                return;
            }
        };
        let mut statuses = statuses.into_iter();
        for (id, sends) in sent {
            let step_statuses: Vec<_> = statuses.by_ref().take(sends.len()).collect();
            match classify(&sends, &step_statuses, block_height) {
                StepStatus::Confirmed { signature } => self.on_confirmed(id, signature).await,
                StepStatus::Failed { reason, code } => self.on_failed(id, reason, code).await,
                StepStatus::Expired => self.on_expired(id).await,
                StepStatus::Pending => {}
            }
        }
    }

    async fn on_failed(&mut self, id: StepId, reason: String, code: Option<u32>) {
        let reprove = code.is_some_and(|code| REPROVE_CODES.contains(&code))
            && self.steps.get(id).is_some_and(|step| {
                step.kind != StepKind::Fill
                    && step.tail.is_empty()
                    && step.prove_attempts < PROVE_ATTEMPTS
            });
        if !reprove {
            let retry = match self.steps.get(id).map(|step| step.kind) {
                Some(StepKind::Fill) => Retry::Fail,
                _ => Retry::Requeue,
            };
            self.abort(id, MakerError::TransactionFailed(reason), retry)
                .await;
            return;
        }
        tracing::warn!(step = id, %reason, "re-proving against fresh roots");
        if let Some(step) = self.steps.get_mut(id) {
            step.sends.clear();
            step.resend_failed = false;
        }
        self.spawn_prove(id);
    }

    async fn on_expired(&mut self, id: StepId) {
        let (exhausted, fill) = self
            .steps
            .get(id)
            .map(|step| {
                (
                    step.resend_failed || step.sends.len() >= SEND_ATTEMPTS,
                    step.kind == StepKind::Fill,
                )
            })
            .unwrap_or((true, false));
        if fill {
            self.abort(id, MakerError::NotLanded, Retry::Fail).await;
        } else if exhausted || self.runtime.cancel.is_cancelled() {
            self.abort(id, MakerError::NotLanded, Retry::Requeue).await;
        } else {
            self.spawn_send(id);
        }
    }

    async fn on_confirmed(&mut self, id: StepId, signature: Signature) {
        let Some(step) = self.steps.get_mut(id) else {
            return;
        };
        step.state = StepState::Confirmed;
        let operation = step.operation;
        let vault_before = step.vault_before;
        let inputs = step.inputs.clone();
        let expected_outputs = step.expected_outputs.clone();
        let settle = step.fill.as_mut().and_then(|fill| fill.settle.take());
        self.services.pending.reservations.remove_spent(&inputs);
        let outputs = expected_outputs.len();
        for wallet in expected_outputs {
            self.services.pending.reservations.insert(TrackedUtxo {
                wallet,
                leaf_index: None,
            });
        }
        self.services.pending.settle(id);
        if let Some(operation) = operation {
            self.services.pending.finish_fill(operation);
        }
        if let Some(settle) = settle {
            let _ = settle.send(Ok(signature));
        }
        if let Some(operation) = operation.and_then(|operation| self.scheduled.remove(&operation)) {
            let receipt = ConsolidateReceipt {
                signature,
                inputs: inputs.len(),
                outputs,
            };
            let outcome = match vault_before {
                Some(vault_before) => OperationOutcome::Rebalanced {
                    receipt,
                    vault_before,
                },
                None => OperationOutcome::Consolidated(receipt),
            };
            let _ = operation.reply.send(Ok(outcome));
        }
        self.steps.prune_confirmed();
        self.send_ready();
        self.try_schedule().await;
    }

    pub async fn abort(&mut self, id: StepId, error: MakerError, retry: Retry) {
        self.discard(id, error, retry).await;
        self.try_schedule().await;
    }

    pub async fn discard(&mut self, id: StepId, error: MakerError, retry: Retry) {
        tracing::warn!(step = id, %error, "aborting step");
        let Some(inputs) = self.steps.get(id).map(|step| step.inputs.clone()) else {
            return;
        };
        self.drop_inputs_spent_elsewhere(&inputs).await;
        let Some(mut step) = self.steps.remove(id) else {
            return;
        };
        self.services.pending.reservations.release(id);
        self.services.pending.settle(id);
        let reason = error.to_string();
        if let Some(settle) = step.fill.as_mut().and_then(|fill| fill.settle.take()) {
            let _ = settle.send(Err(error));
        }
        let Some(operation_id) = step.operation else {
            return;
        };
        let Some(mut operation) = self.scheduled.remove(&operation_id) else {
            self.services.pending.drop_fill(operation_id);
            return;
        };
        operation.attempts += 1;
        if retry == Retry::Fail || operation.attempts >= OPERATION_ATTEMPTS {
            let attempts = operation.attempts;
            self.fail(operation, MakerError::OperationFailed { attempts, reason });
            return;
        }
        match self
            .services
            .pending
            .queue(operation.operation.asset(), operation.operation.amount())
        {
            Ok(()) => self.queue.push_front(operation),
            Err(error) => self.fail(operation, error),
        }
    }

    async fn drop_inputs_spent_elsewhere(&mut self, inputs: &[[u8; 32]]) {
        let tracked: Vec<TrackedUtxo> = inputs
            .iter()
            .filter_map(|hash| self.services.pending.reservations.get(hash))
            .collect();
        if tracked.is_empty() {
            return;
        }
        let nullifier_pdas: Vec<Address> = tracked
            .iter()
            .map(|utxo| {
                pda::nullifier_pda(&pda::tree(utxo.wallet.tree_id), &utxo.wallet.nullifier).0
            })
            .collect();
        match self
            .services
            .rpc
            .get_multiple_accounts(nullifier_pdas)
            .await
        {
            Ok(accounts) => {
                for (utxo, account) in tracked.iter().zip(accounts) {
                    if account.is_some() {
                        tracing::warn!("dropping a utxo spent outside this market maker");
                        self.services
                            .pending
                            .reservations
                            .remove_spent(&[utxo.utxo_hash()]);
                    }
                }
            }
            Err(error) => tracing::warn!(%error, "nullifier pda check failed"),
        }
    }
}

pub async fn confirm_indexed(services: &Services, signature: Signature) -> Result<(), MakerError> {
    let poll = IndexerPollConfig::default();
    let mut confirmed = false;
    for delay in std::iter::once(Duration::ZERO).chain(poll.backoff()) {
        tokio::time::sleep(delay).await;
        if !confirmed {
            confirmed = services
                .rpc
                .confirm_transaction(signature)
                .await
                .map_err(MakerError::Rpc)?;
        }
        if confirmed
            && !services
                .indexer
                .get_shielded_transactions_by_signature(signature, None)
                .await
                .map_err(MakerError::Indexer)?
                .transactions
                .is_empty()
        {
            return Ok(());
        }
    }
    if confirmed {
        Err(MakerError::NotIndexed { signature })
    } else {
        Err(MakerError::NotConfirmed { signature })
    }
}
