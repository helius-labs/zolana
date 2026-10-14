use std::time::Duration;

use custom_ring_interface::{compute_unit_limit, CustomRingError, InstructionTag};
use solana_address::Address;
use solana_commitment_config::CommitmentLevel;
use solana_instruction::Instruction;
use solana_instruction_error::InstructionError;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_error::TransactionError;
use solana_transaction_status_client_types::{TransactionConfirmationStatus, TransactionStatus};
use zolana_client::{
    compile_message, sign_transaction, AsyncIndexer, AsyncRpc, AsyncZolanaClient,
    ComputeBudgetConfig, RpcSendTransactionConfig,
};

use crate::{
    CustomRingTransfer, DelegateTransfer, MergeProofInput, PreparedCustomRingMerge,
    PreparedRingDeposit, RegisterKey, RegisterSpend, RingError,
};

const MAX_ATTEMPTS: u8 = 3;
const PENDING_POLL: Duration = Duration::from_millis(500);
const SLOT_POLL: Duration = Duration::from_millis(400);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmissionStatus {
    Confirmed {
        signature: Signature,
        slot: u64,
    },
    Failed {
        signature: Signature,
        error: TransactionError,
    },
    Pending {
        signature: Signature,
    },
}

/// A [`SubmissionStatus`] past its pending state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettledSubmission {
    Confirmed {
        signature: Signature,
        slot: u64,
    },
    Failed {
        signature: Signature,
        error: TransactionError,
    },
}

pub enum RingOperation<'a> {
    Transfer(Box<CustomRingTransfer<'a>>),
    Delegate(Box<DelegateTransfer<'a>>),
    RegisterSpend(RegisterSpend),
    RegisterKey(RegisterKey<'a>),
    Merge(Box<RingMergeOperation>),
    Deposit(Box<PreparedRingDeposit>),
    /// A built instruction, sent as is, its budget from its tag.
    Instruction(Instruction),
}

pub struct RingMergeOperation {
    prepared: PreparedCustomRingMerge,
    input: MergeProofInput,
    cosigner: Option<Address>,
}

impl RingMergeOperation {
    pub fn new(prepared: PreparedCustomRingMerge, input: MergeProofInput) -> Self {
        Self {
            prepared,
            input,
            cosigner: None,
        }
    }

    #[must_use]
    pub fn with_cosigner(mut self, cosigner: Address) -> Self {
        self.cosigner = Some(cosigner);
        self
    }
}

macro_rules! operations {
    ($($variant:ident($ty:ty) => $wrap:expr,)*) => {$(
        impl<'a> From<$ty> for RingOperation<'a> {
            fn from(value: $ty) -> Self {
                Self::$variant($wrap(value))
            }
        }
    )*};
}

operations! {
    Transfer(CustomRingTransfer<'a>) => Box::new,
    Delegate(DelegateTransfer<'a>) => Box::new,
    RegisterSpend(RegisterSpend) => core::convert::identity,
    RegisterKey(RegisterKey<'a>) => core::convert::identity,
    Merge(RingMergeOperation) => Box::new,
    Deposit(PreparedRingDeposit) => Box::new,
    Instruction(Instruction) => core::convert::identity,
}

/// What a signed attempt proved, the window its statement fixed included.
struct Proved {
    instruction: Instruction,
    budget: ComputeBudgetConfig,
    /// `(window_slots, window_index)` of a windowed statement.
    window: Option<(u64, u64)>,
}

struct Attempt {
    transaction: VersionedTransaction,
    window: Option<(u64, u64)>,
    last_valid_block_height: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Unknown,
    Confirmed { slot: u64 },
    Failed(TransactionError),
}

#[must_use]
pub struct RingSubmission<'a> {
    operation: RingOperation<'a>,
    pending: Option<Attempt>,
    attempts: u8,
    terminal: Option<SubmissionStatus>,
}

impl<'a> RingSubmission<'a> {
    pub fn new(operation: impl Into<RingOperation<'a>>) -> Self {
        Self {
            operation: operation.into(),
            pending: None,
            attempts: 0,
            terminal: None,
        }
    }

    pub fn pending_transaction(&self) -> Option<&VersionedTransaction> {
        self.pending.as_ref().map(|attempt| &attempt.transaction)
    }

    pub fn attempts(&self) -> u8 {
        self.attempts
    }

    /// Inputs stay reserved while the sent signature is unresolved. A closing window
    /// is waited out and proved again without counting an attempt.
    pub async fn send<R: AsyncRpc, I: AsyncIndexer>(
        &mut self,
        client: &AsyncZolanaClient<R, I>,
        payer: &(dyn Signer + Sync),
        signers: &[&(dyn Signer + Sync)],
    ) -> Result<SubmissionStatus, RingError> {
        if let Some(terminal) = &self.terminal {
            return Ok(terminal.clone());
        }
        loop {
            let failure = match &self.pending {
                Some(_) => None,
                None => {
                    let proved = match self.operation.prove(client, payer.pubkey()).await {
                        Err(RingError::WindowClosing { resumes_at }) => {
                            wait_for_slot(client, resumes_at).await?;
                            continue;
                        }
                        proved => proved?,
                    };
                    let (blockhash, last_valid_block_height) =
                        client.get_latest_blockhash().await?;
                    let message = compile_message(
                        &payer.pubkey(),
                        &[proved.instruction],
                        blockhash,
                        proved.budget,
                    )?;
                    // The signer list is not `Send`, it ends before the next await.
                    let transaction = {
                        let mut all: Vec<&dyn Signer> = vec![payer];
                        all.extend(signers.iter().map(|signer| *signer as &dyn Signer));
                        sign_transaction(message, &all)?
                    };
                    self.attempts += 1;
                    let config = RpcSendTransactionConfig {
                        preflight_commitment: Some(CommitmentLevel::Confirmed),
                        ..RpcSendTransactionConfig::default()
                    };
                    let failure = client
                        .send_transaction_with_config(&transaction, config)
                        .await
                        .err()
                        .and_then(|error| error.transaction_error());
                    self.pending = Some(Attempt {
                        transaction,
                        window: proved.window,
                        last_valid_block_height,
                    });
                    failure
                }
            };
            let attempt = self.pending.as_ref().ok_or(RingError::IncompleteProofSet)?;
            let signature = attempt.transaction.signatures[0];
            let outcome = match failure {
                Some(error) => Outcome::Failed(error),
                None => outcome(client, signature, attempt.last_valid_block_height).await?,
            };
            let advanced = match (attempt.window, &outcome) {
                (Some((slots, index)), Outcome::Failed(error))
                    if ring_error(error)
                        == Some(CustomRingError::ProofVerificationFailed as u32) =>
                {
                    client.get_slot().await? / slots != index
                }
                _ => false,
            };
            if let Some(status) = self.settle(signature, outcome, advanced) {
                return Ok(status);
            }
        }
    }

    pub async fn send_until_settled<R: AsyncRpc, I: AsyncIndexer>(
        &mut self,
        client: &AsyncZolanaClient<R, I>,
        payer: &(dyn Signer + Sync),
        signers: &[&(dyn Signer + Sync)],
    ) -> Result<SettledSubmission, RingError> {
        loop {
            match self.send(client, payer, signers).await? {
                SubmissionStatus::Confirmed { signature, slot } => {
                    return Ok(SettledSubmission::Confirmed { signature, slot })
                }
                SubmissionStatus::Failed { signature, error } => {
                    return Ok(SettledSubmission::Failed { signature, error })
                }
                SubmissionStatus::Pending { .. } => tokio::time::sleep(PENDING_POLL).await,
            }
        }
    }

    /// `None` re-proves a retryable failure below the attempt limit.
    fn settle(
        &mut self,
        signature: Signature,
        outcome: Outcome,
        window_advanced: bool,
    ) -> Option<SubmissionStatus> {
        let terminal = match outcome {
            Outcome::Unknown => return Some(SubmissionStatus::Pending { signature }),
            Outcome::Confirmed { slot } => SubmissionStatus::Confirmed { signature, slot },
            Outcome::Failed(error) => {
                self.pending = None;
                if retryable(&error, window_advanced) && self.attempts < MAX_ATTEMPTS {
                    return None;
                }
                SubmissionStatus::Failed { signature, error }
            }
        };
        self.pending = None;
        self.terminal = Some(terminal.clone());
        Some(terminal)
    }
}

impl RingOperation<'_> {
    async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
        payer: Address,
    ) -> Result<Proved, RingError> {
        let proved = |instruction, tag, window| Proved {
            instruction,
            budget: ComputeBudgetConfig::new(compute_unit_limit(tag)),
            window,
        };
        Ok(match self {
            Self::Transfer(transfer) => {
                let proven = transfer.prove(client).await?;
                proved(
                    proven.instruction()?,
                    InstructionTag::Transact,
                    proven.window,
                )
            }
            Self::Delegate(transfer) => {
                let proven = transfer.prove(client).await?;
                proved(
                    proven.instruction()?,
                    InstructionTag::DelegateTransact,
                    None,
                )
            }
            Self::RegisterSpend(registration) => {
                let proven = registration.prove(client).await?;
                let window = Some(proven.window);
                proved(proven.instruction()?, InstructionTag::RegisterSpend, window)
            }
            Self::RegisterKey(registration) => {
                let proven = registration.prove(client).await?;
                proved(proven.instruction()?, InstructionTag::RegisterKey, None)
            }
            Self::Merge(operation) => {
                let mut proven = operation
                    .prepared
                    .clone()
                    .prove(operation.input.clone(), client)
                    .await?;
                if let Some(cosigner) = operation.cosigner {
                    proven = proven.with_cosigner(cosigner);
                }
                proved(proven.instruction(payer), InstructionTag::Merge, None)
            }
            Self::Deposit(deposit) => Proved {
                instruction: deposit.prove(client).await?,
                budget: deposit.budget(),
                window: None,
            },
            Self::Instruction(instruction) => {
                let tag = instruction
                    .data
                    .first()
                    .and_then(|tag| InstructionTag::try_from(*tag).ok())
                    .ok_or(CustomRingError::InvalidInstructionData)?;
                proved(instruction.clone(), tag, None)
            }
        })
    }
}

async fn wait_for_slot(client: &(impl AsyncRpc + ?Sized), slot: u64) -> Result<(), RingError> {
    while client.get_slot().await? < slot {
        tokio::time::sleep(SLOT_POLL).await;
    }
    Ok(())
}

/// A failed lookup cannot release the attempt, an expiry needs a fresh absent lookup.
async fn outcome(
    client: &(impl AsyncRpc + ?Sized),
    signature: Signature,
    last_valid_block_height: u64,
) -> Result<Outcome, RingError> {
    if let Some(outcome) = observe(client, signature).await {
        return Ok(outcome);
    }
    if client.get_block_height().await? <= last_valid_block_height {
        return Ok(Outcome::Unknown);
    }
    // The transaction can land between the first lookup and the expiry check.
    Ok(observe(client, signature)
        .await
        .unwrap_or(Outcome::Failed(TransactionError::BlockhashNotFound)))
}

/// `None` for a signature the cluster does not know, `Unknown` for an unresolved lookup.
async fn observe(client: &(impl AsyncRpc + ?Sized), signature: Signature) -> Option<Outcome> {
    let Ok(statuses) = client
        .get_signature_statuses_with_history(vec![signature])
        .await
    else {
        return Some(Outcome::Unknown);
    };
    decode_status(statuses)
}

fn decode_status(statuses: Vec<Option<TransactionStatus>>) -> Option<Outcome> {
    let Ok([status]) = <[_; 1]>::try_from(statuses) else {
        return Some(Outcome::Unknown);
    };
    let status = status?;
    if !matches!(
        status.confirmation_status,
        Some(TransactionConfirmationStatus::Confirmed | TransactionConfirmationStatus::Finalized)
    ) {
        return Some(Outcome::Unknown);
    }
    Some(match status.err {
        None => Outcome::Confirmed { slot: status.slot },
        Some(error) => Outcome::Failed(error),
    })
}

/// The attempt compiles a one-instruction message.
fn ring_error(error: &TransactionError) -> Option<u32> {
    match error {
        TransactionError::InstructionError(0, InstructionError::Custom(code)) => Some(*code),
        _ => None,
    }
}

fn retryable(error: &TransactionError, window_advanced: bool) -> bool {
    matches!(error, TransactionError::BlockhashNotFound)
        || ring_error(error) == Some(CustomRingError::StaleKeyRegistryRoot as u32)
        || (window_advanced
            && ring_error(error) == Some(CustomRingError::ProofVerificationFailed as u32))
}
