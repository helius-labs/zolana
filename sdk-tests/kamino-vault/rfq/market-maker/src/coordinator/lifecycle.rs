use std::time::Instant;

use solana_address::Address;
use solana_instruction::Instruction;
use solana_signature::Signature;
use tokio::sync::oneshot;
use zolana_client::compile_message;
use zolana_interface::{error::ShieldedPoolError, pda};

use super::{ConsolidateReceipt, Coordinator, Event, OperationOutcome};
use kamino_vault_rfq_sdk::swap::{Fill, SWAP_COMPUTE_BUDGET};

use crate::{
    error::MakerError,
    send::{classify, SendOutcome, SendRequest, Sent, StepStatus},
    step::{StepId, StepKind, StepState},
    tracker::TrackedUtxo,
};

const OPERATION_ATTEMPTS: u32 = 3;
const PROVE_ATTEMPTS: u32 = 3;
const SEND_ATTEMPTS: usize = 5;
const REPROVE_CODES: [u32; 2] = [
    ShieldedPoolError::TransactProofVerificationFailed as u32,
    ShieldedPoolError::StaleNullifierRoot as u32,
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Retry {
    Requeue,
    Fail,
}

impl Coordinator {
    pub(super) fn spawn_prove(&mut self, id: StepId) {
        let Some(step) = self.steps.get_mut(id) else {
            return;
        };
        let Some(work) = step.proof.clone() else {
            return;
        };
        step.state = StepState::Proving;
        step.instruction = None;
        step.prove_attempts += 1;
        let proofs = self.proofs.clone();
        let events = self.events.clone();
        let cancel = self.cancel.clone();
        self.tasks.spawn(async move {
            if let Some(result) = cancel.run_until_cancelled(proofs.prove(work)).await {
                let _ = events.send(Event::Proven { step: id, result });
            }
        });
    }

    pub(super) async fn on_proven(&mut self, id: StepId, result: Result<Instruction, MakerError>) {
        let Some(step) = self.steps.get_mut(id) else {
            return;
        };
        match result {
            Ok(instruction) => {
                step.instruction = Some(instruction);
                step.state = StepState::Proven;
                if step.kind == StepKind::Fill {
                    self.offer_fill(id).await;
                    return;
                }
                let fits = self
                    .send_request(id)
                    .map(|request| self.sender.check_size(&request));
                match fits {
                    Some(Err(error)) => self.abort(id, error, Retry::Fail).await,
                    _ => self.send_ready(),
                }
            }
            Err(error) if step.prove_attempts < PROVE_ATTEMPTS => {
                tracing::warn!(step = id, %error, "proof failed, retrying");
                self.spawn_prove(id);
            }
            Err(error) => self.abort(id, error, Retry::Requeue).await,
        }
    }

    async fn offer_fill(&mut self, id: StepId) {
        let legs = self.steps.get(id).and_then(|step| {
            let fill = step.fill.as_ref()?;
            Some([fill.user_leg.clone(), step.instruction.clone()?])
        });
        let Some(legs) = legs else {
            return;
        };
        if let Err(error) = self.budget.check(&legs) {
            self.abort(id, error.into(), Retry::Fail).await;
            return;
        }
        let (blockhash, last_valid_block_height) = match self.sender.latest_blockhash().await {
            Ok(latest) => latest,
            Err(error) => {
                self.abort(id, error, Retry::Requeue).await;
                return;
            }
        };
        let message = match compile_message(&self.payer, &legs, blockhash, SWAP_COMPUTE_BUDGET) {
            Ok(message) => message,
            Err(error) => {
                self.abort(id, error.into(), Retry::Fail).await;
                return;
            }
        };
        let Some(step) = self.steps.get_mut(id) else {
            return;
        };
        let Some(fill) = step.fill.as_mut() else {
            return;
        };
        let expires_at = Instant::now() + fill.ttl;
        fill.message = Some(message.clone());
        fill.last_valid_block_height = last_valid_block_height;
        fill.expires_at = Some(expires_at);
        step.state = StepState::AwaitingSignature;
        let leg = Fill {
            step: id,
            message,
            spent: fill.spends.clone(),
            change: step.expected_outputs.clone(),
            expires_at,
        };
        let operation = step
            .operation
            .and_then(|operation| self.scheduled.remove(&operation));
        let events = self.events.clone();
        let cancel = self.cancel.clone();
        self.tasks.spawn(async move {
            let deadline = tokio::time::sleep_until(expires_at.into());
            if cancel.run_until_cancelled(deadline).await.is_some() {
                let _ = events.send(Event::Expire(id));
            }
        });
        let delivered = operation.is_some_and(|operation| {
            operation
                .reply
                .send(Ok(OperationOutcome::Filled(leg)))
                .is_ok()
        });
        if !delivered {
            self.discard(id, MakerError::ReservationExpired { step: id }, Retry::Fail)
                .await;
            self.try_schedule().await;
        }
    }

    pub(super) async fn on_settle(
        &mut self,
        id: StepId,
        user_signature: Signature,
        reply: oneshot::Sender<Result<Signature, MakerError>>,
    ) {
        let Some(step) = self.steps.get_mut(id) else {
            let _ = reply.send(Err(MakerError::UnknownFill { step: id }));
            return;
        };
        if step.state != StepState::AwaitingSignature {
            let _ = reply.send(Err(MakerError::AlreadySettling { step: id }));
            return;
        }
        let Some(fill) = step.fill.as_mut() else {
            let _ = reply.send(Err(MakerError::UnknownFill { step: id }));
            return;
        };
        if fill
            .expires_at
            .is_none_or(|deadline| Instant::now() >= deadline)
        {
            let _ = reply.send(Err(MakerError::ReservationExpired { step: id }));
            self.discard(id, MakerError::ReservationExpired { step: id }, Retry::Fail)
                .await;
            self.try_schedule().await;
            return;
        }
        let Some(message) = fill.message.clone() else {
            let _ = reply.send(Err(MakerError::UnknownFill { step: id }));
            return;
        };
        match self.sender.sign_swap(message, user_signature) {
            Ok(transaction) => {
                fill.transaction = Some(transaction);
                fill.settle = Some(reply);
                self.spawn_send(id);
            }
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        }
    }

    pub(super) async fn on_expire(&mut self, id: StepId) {
        let expired = self.steps.get(id).is_some_and(|step| {
            step.state == StepState::AwaitingSignature
                && step
                    .fill
                    .as_ref()
                    .and_then(|fill| fill.expires_at)
                    .is_some_and(|deadline| Instant::now() >= deadline)
        });
        if expired {
            self.abort(id, MakerError::ReservationExpired { step: id }, Retry::Fail)
                .await;
        }
    }

    fn send_request(&self, id: StepId) -> Option<SendRequest> {
        let step = self.steps.get(id)?;
        let instruction = step.instruction.clone()?;
        Some(SendRequest {
            instructions: std::iter::once(instruction)
                .chain(step.tail.iter().cloned())
                .collect(),
            compute_units: step.compute_units(),
        })
    }

    pub(super) fn send_ready(&mut self) {
        if self.cancel.is_cancelled() {
            return;
        }
        for id in self.steps.ready_to_send() {
            self.spawn_send(id);
        }
    }

    fn spawn_send(&mut self, id: StepId) {
        let signed = self.steps.get(id).and_then(|step| {
            let fill = step.fill.as_ref()?;
            Some((fill.transaction.clone()?, fill.last_valid_block_height))
        });
        let request = match signed {
            Some(_) => None,
            None => match self.send_request(id) {
                Some(request) => Some(request),
                None => return,
            },
        };
        if let Some(step) = self.steps.get_mut(id) {
            step.state = StepState::Sending;
        }
        let sender = self.sender.clone();
        let events = self.events.clone();
        self.tasks.spawn(async move {
            let outcome = match (signed, request) {
                (Some((transaction, last_valid)), _) => {
                    sender.submit(&transaction, last_valid).await
                }
                (None, Some(request)) => sender.send(&request).await,
                (None, None) => return,
            };
            let _ = events.send(Event::Sent { step: id, outcome });
        });
    }

    pub(super) async fn on_sent(&mut self, id: StepId, outcome: SendOutcome) {
        let Some(step) = self.steps.get_mut(id) else {
            return;
        };
        match outcome {
            SendOutcome::Sent(sent) => {
                step.sends.push(sent);
                step.state = StepState::Sent;
            }
            SendOutcome::OutcomeUnknown { sent, error } => {
                tracing::warn!(step = id, %error, "send outcome unknown, polling its signature");
                step.sends.push(sent);
                step.state = StepState::Sent;
            }
            SendOutcome::NotSent(error) => {
                tracing::warn!(step = id, %error, "step was not sent, retrying");
                step.state = StepState::Proven;
                if step.kind == StepKind::Fill {
                    self.spawn_send(id);
                }
            }
            SendOutcome::Rejected(error) if step.sends.is_empty() => {
                let retry = match step.kind {
                    StepKind::Fill => Retry::Fail,
                    _ => Retry::Requeue,
                };
                self.abort(id, error, retry).await;
            }
            SendOutcome::Rejected(error) => {
                tracing::warn!(step = id, %error, "resend rejected, polling earlier signatures");
                step.resend_failed = true;
                step.state = StepState::Sent;
            }
        }
    }

    pub(super) async fn poll_statuses(&mut self) {
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
            self.sender.statuses(&signatures),
            self.sender.block_height()
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
        } else if exhausted || self.cancel.is_cancelled() {
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
        self.ledger.tracker.remove_spent(&inputs);
        let outputs = expected_outputs.len();
        for wallet in expected_outputs {
            self.ledger.tracker.insert(TrackedUtxo {
                wallet,
                leaf_index: None,
            });
        }
        self.ledger.settle(id);
        if let Some(settle) = settle {
            let _ = settle.send(Ok(signature));
        }
        if let Some(operation) = operation.and_then(|operation| self.scheduled.remove(&operation)) {
            let _ = operation.reply.send(Ok(OperationOutcome::Consolidated {
                receipt: ConsolidateReceipt {
                    signature,
                    inputs: inputs.len(),
                    outputs,
                },
                vault_before,
            }));
        }
        self.steps.prune_confirmed();
        self.send_ready();
        self.try_schedule().await;
    }

    pub(super) async fn abort(&mut self, id: StepId, error: MakerError, retry: Retry) {
        self.discard(id, error, retry).await;
        self.try_schedule().await;
    }

    pub(super) async fn discard(&mut self, id: StepId, error: MakerError, retry: Retry) {
        tracing::warn!(step = id, %error, "aborting step");
        let Some(inputs) = self.steps.get(id).map(|step| step.inputs.clone()) else {
            return;
        };
        self.drop_inputs_spent_elsewhere(&inputs).await;
        let Some(mut step) = self.steps.remove(id) else {
            return;
        };
        self.ledger.tracker.release(id);
        self.ledger.discard(id);
        let reason = error.to_string();
        if let Some(settle) = step.fill.as_mut().and_then(|fill| fill.settle.take()) {
            let _ = settle.send(Err(error));
        }
        let Some(mut operation) = step
            .operation
            .and_then(|operation| self.scheduled.remove(&operation))
        else {
            return;
        };
        operation.attempts += 1;
        if retry == Retry::Fail || operation.attempts >= OPERATION_ATTEMPTS {
            let _ = operation.reply.send(Err(MakerError::OperationFailed {
                attempts: operation.attempts,
                reason,
            }));
            return;
        }
        match self
            .ledger
            .queue(operation.operation.asset(), operation.operation.amount())
        {
            Ok(()) => self.queue.push_front(operation),
            Err(error) => {
                let _ = operation.reply.send(Err(error));
            }
        }
    }

    async fn drop_inputs_spent_elsewhere(&mut self, inputs: &[[u8; 32]]) {
        let tracked: Vec<TrackedUtxo> = inputs
            .iter()
            .filter_map(|hash| self.ledger.tracker.get(hash))
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
        match self.rpc.get_multiple_accounts(nullifier_pdas).await {
            Ok(accounts) => {
                for (utxo, account) in tracked.iter().zip(accounts) {
                    if account.is_some() {
                        tracing::warn!("dropping a utxo spent outside this market maker");
                        self.ledger.tracker.remove_spent(&[utxo.utxo_hash()]);
                    }
                }
            }
            Err(error) => tracing::warn!(%error, "nullifier pda check failed"),
        }
    }
}
