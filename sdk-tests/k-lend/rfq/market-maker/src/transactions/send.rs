use std::sync::Arc;

use solana_address::Address;
use solana_commitment_config::{CommitmentConfig, CommitmentLevel};
use solana_instruction::Instruction;
use solana_instruction_error::InstructionError;
use solana_rpc_client_api::{
    client_error::ErrorKind, config::RpcSendTransactionConfig, request::RpcError,
};
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_error::TransactionError;
use solana_transaction_status_client_types::TransactionStatus;
use zolana_client::{
    compile_message, sign_transaction, transaction_size, AsyncRpc, ClientError, ComputeBudgetConfig,
};
use zolana_keypair::ShieldedKeypair;

use super::{
    confirm::Retry,
    coordinator::{Coordinator, Event},
    steps::{StepId, StepKind, StepState},
};
use crate::error::MakerError;

const STATUS_BATCH: usize = 256;

#[derive(Clone)]
pub struct SendRequest {
    pub instructions: Vec<Instruction>,
    pub compute_units: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sent {
    pub signature: Signature,
    pub last_valid_block_height: u64,
}

#[derive(Debug)]
pub enum SendOutcome {
    Sent(Sent),
    OutcomeUnknown { sent: Sent, error: ClientError },
    Rejected(MakerError),
    NotSent(MakerError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepStatus {
    Confirmed { signature: Signature },
    Failed { reason: String, code: Option<u32> },
    Expired,
    Pending,
}

pub struct SendQueue {
    rpc: Arc<dyn AsyncRpc>,
    signer: Arc<ShieldedKeypair>,
    payer: Address,
}

impl SendQueue {
    pub fn new(rpc: Arc<dyn AsyncRpc>, signer: Arc<ShieldedKeypair>) -> Self {
        let payer = signer.pubkey();
        Self { rpc, signer, payer }
    }

    pub fn check_size(&self, request: &SendRequest) -> Result<(), MakerError> {
        let size = transaction_size(
            &self.payer,
            &request.instructions,
            ComputeBudgetConfig::new(request.compute_units),
        )?;
        if size.fits() {
            Ok(())
        } else {
            Err(MakerError::TransactionTooLarge {
                bytes: size.bytes,
                addresses: size.addresses,
            })
        }
    }

    pub async fn latest_blockhash(&self) -> Result<(solana_hash::Hash, u64), MakerError> {
        self.rpc
            .get_latest_blockhash()
            .await
            .map_err(MakerError::Rpc)
    }

    pub async fn send(&self, request: &SendRequest) -> SendOutcome {
        let (blockhash, last_valid_block_height) = match self.latest_blockhash().await {
            Ok(latest) => latest,
            Err(error) => return SendOutcome::NotSent(error),
        };
        let message = match compile_message(
            &self.payer,
            &request.instructions,
            blockhash,
            ComputeBudgetConfig::new(request.compute_units),
        ) {
            Ok(message) => message,
            Err(error) => return SendOutcome::Rejected(error.into()),
        };
        let transaction = match sign_transaction(message, &[self.signer.as_ref() as &dyn Signer]) {
            Ok(transaction) => transaction,
            Err(error) => return SendOutcome::NotSent(error.into()),
        };
        self.submit(&transaction, last_valid_block_height).await
    }

    pub async fn submit(
        &self,
        transaction: &VersionedTransaction,
        last_valid_block_height: u64,
    ) -> SendOutcome {
        let Some(signature) = transaction.signatures.first().copied() else {
            return SendOutcome::Rejected(MakerError::UnsignedMessage);
        };
        let sent = Sent {
            signature,
            last_valid_block_height,
        };
        let config = RpcSendTransactionConfig {
            preflight_commitment: Some(CommitmentLevel::Confirmed),
            max_retries: Some(0),
            ..RpcSendTransactionConfig::default()
        };
        match self
            .rpc
            .send_transaction_with_config(transaction, config)
            .await
        {
            Ok(_) => SendOutcome::Sent(sent),
            Err(error) if is_rejection(&error) => {
                SendOutcome::Rejected(MakerError::SendRejected(error.to_string()))
            }
            Err(error) => SendOutcome::OutcomeUnknown { sent, error },
        }
    }

    pub async fn statuses(
        &self,
        signatures: &[Signature],
    ) -> Result<Vec<Option<TransactionStatus>>, MakerError> {
        let mut statuses = Vec::with_capacity(signatures.len());
        for batch in signatures.chunks(STATUS_BATCH) {
            statuses.extend(
                self.rpc
                    .get_signature_statuses(batch.to_vec())
                    .await
                    .map_err(MakerError::Rpc)?,
            );
        }
        Ok(statuses)
    }

    pub async fn block_height(&self) -> Result<u64, MakerError> {
        self.rpc.get_block_height().await.map_err(MakerError::Rpc)
    }
}

fn is_rejection(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::SolanaRpcTransaction { source, .. }
            if matches!(source.kind(), ErrorKind::RpcError(RpcError::RpcResponseError { .. }))
    )
}

pub fn classify(
    sends: &[Sent],
    statuses: &[Option<TransactionStatus>],
    block_height: u64,
) -> StepStatus {
    let mut failure = None;
    for (sent, status) in sends.iter().zip(statuses) {
        let Some(status) = status else {
            continue;
        };
        match &status.err {
            None if status.satisfies_commitment(CommitmentConfig::confirmed()) => {
                return StepStatus::Confirmed {
                    signature: sent.signature,
                };
            }
            None => {}
            Some(error) => {
                failure = Some(StepStatus::Failed {
                    reason: error.to_string(),
                    code: custom_code(error),
                })
            }
        }
    }
    if let Some(failure) = failure {
        return failure;
    }
    let last_valid = sends
        .iter()
        .map(|sent| sent.last_valid_block_height)
        .max()
        .unwrap_or(0);
    if block_height > last_valid {
        StepStatus::Expired
    } else {
        StepStatus::Pending
    }
}

fn custom_code(error: &TransactionError) -> Option<u32> {
    match error {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => Some(*code),
        _ => None,
    }
}

impl Coordinator {
    pub fn send_request(&self, id: StepId) -> Option<SendRequest> {
        let step = self.steps.get(id)?;
        let instruction = step.instruction.clone()?;
        Some(SendRequest {
            instructions: std::iter::once(instruction)
                .chain(step.tail.iter().cloned())
                .collect(),
            compute_units: step.compute_units(),
        })
    }

    pub fn send_ready(&mut self) {
        if self.runtime.cancel.is_cancelled() {
            return;
        }
        for id in self.steps.ready_to_send() {
            self.spawn_send(id);
        }
    }

    pub fn spawn_send(&mut self, id: StepId) {
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
        let sender = self.services.sender.clone();
        let events = self.runtime.events.clone();
        self.runtime.tasks.spawn(async move {
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

    pub async fn on_sent(&mut self, id: StepId, outcome: SendOutcome) {
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
}
