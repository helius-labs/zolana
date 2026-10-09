use std::sync::Arc;

use solana_address::Address;
use solana_commitment_config::{CommitmentConfig, CommitmentLevel};
use solana_instruction::Instruction;
use solana_instruction_error::InstructionError;
use solana_message::VersionedMessage;
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

use super::error::MakerError;

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

    pub fn sign_swap(
        &self,
        message: VersionedMessage,
        user_signature: Signature,
    ) -> Result<VersionedTransaction, MakerError> {
        let required = usize::from(message.header().num_required_signatures);
        let accounts = message.static_account_keys();
        let signers = accounts
            .get(..required)
            .ok_or(MakerError::MalformedMessage {
                required,
                accounts: accounts.len(),
            })?
            .to_vec();
        let (maker, users): (Vec<Address>, Vec<Address>) =
            signers.iter().partition(|signer| **signer == self.payer);
        if maker.is_empty() {
            return Err(MakerError::UnsignedMessage);
        }
        if let Some(extra) = users.get(1) {
            return Err(MakerError::UnexpectedSigner { signer: *extra });
        }
        let serialized = message.serialize();
        let maker_signature = self
            .signer
            .try_sign_message(&serialized)
            .map_err(|source| MakerError::Signer {
                pubkey: self.payer,
                source,
            })?;
        let signatures = signers
            .iter()
            .map(|signer| {
                if *signer == self.payer {
                    maker_signature
                } else {
                    user_signature
                }
            })
            .collect();
        Ok(VersionedTransaction {
            signatures,
            message,
        })
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
