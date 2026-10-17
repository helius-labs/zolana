use std::time::Duration;

use custom_ring_interface::{compute_unit_limit, CustomRingError, InstructionTag, KeyRegistryRoot};
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
    heap::boxed, CustomRing, CustomRingTransfer, DelegateTransfer, EscrowBinding, MergeProofInput,
    PreparedCustomRingMerge, PreparedRingDeposit, RegisterKey, RingError,
};

const MAX_ATTEMPTS: u8 = 3;
const PENDING_POLL: Duration = Duration::from_millis(500);

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
    RegisterKey(RegisterKey<'a>) => core::convert::identity,
    Merge(RingMergeOperation) => Box::new,
    Deposit(PreparedRingDeposit) => Box::new,
    Instruction(Instruction) => core::convert::identity,
}

struct Proved {
    instruction: Instruction,
    budget: ComputeBudgetConfig,
    bound: Option<BoundRoot>,
}

struct Attempt {
    transaction: VersionedTransaction,
    bound: Option<BoundRoot>,
    last_valid_block_height: u64,
}

/// The registry history slot an escrowed statement names and the root it proved against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BoundRoot {
    ring: CustomRing,
    index: u8,
    root: [u8; 32],
}

impl BoundRoot {
    pub(crate) fn of(ring: CustomRing, escrow: EscrowBinding) -> Option<Self> {
        match escrow {
            EscrowBinding::Off => None,
            EscrowBinding::Registry { root_index, root } => Some(Self {
                ring,
                index: root_index,
                root,
            }),
        }
    }

    /// Later registrations wrapped the history over the slot, so the program read another root.
    async fn replaced(self, client: &(impl AsyncRpc + ?Sized)) -> Result<bool, RingError> {
        let registry = self
            .ring
            .read::<KeyRegistryRoot>(client, &[KeyRegistryRoot::SEED], true)
            .await?;
        Ok(registry.is_some_and(|registry| registry.root_at(self.index) != Some(self.root)))
    }
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

    /// Inputs stay reserved while the sent signature is unresolved.
    pub async fn send<R: AsyncRpc, I: AsyncIndexer>(
        &mut self,
        client: &AsyncZolanaClient<R, I>,
        payer: &(dyn Signer + Sync),
        signers: &[&(dyn Signer + Sync)],
    ) -> Result<SubmissionStatus, RingError> {
        if let RingOperation::Deposit(deposit) = &self.operation {
            deposit.check_public_signers(
                core::iter::once(payer.pubkey())
                    .chain(signers.iter().map(|signer| signer.pubkey())),
            )?;
        }
        if let Some(terminal) = &self.terminal {
            return Ok(terminal.clone());
        }
        loop {
            let failure = match &self.pending {
                Some(_) => None,
                None => {
                    let proved = boxed(|| self.operation.prove(client, payer.pubkey())).await?;
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
                        bound: proved.bound,
                        last_valid_block_height,
                    });
                    failure
                }
            };
            let attempt = self.pending.as_ref().ok_or(RingError::IncompleteProofSet)?;
            let signature = attempt.transaction.signatures[0];
            let bound = attempt.bound;
            let outcome = match failure {
                Some(error) => Outcome::Failed(error),
                None => outcome(client, signature, attempt.last_valid_block_height).await?,
            };
            let root_replaced = match (&outcome, bound) {
                (Outcome::Failed(error), Some(bound))
                    if ring_error(error)
                        == Some(CustomRingError::ProofVerificationFailed as u32) =>
                {
                    bound.replaced(client).await?
                }
                _ => false,
            };
            if let Some(status) = self.settle(signature, outcome, root_replaced) {
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
            match boxed(|| self.send(client, payer, signers)).await? {
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
        root_replaced: bool,
    ) -> Option<SubmissionStatus> {
        let terminal = match outcome {
            Outcome::Unknown => return Some(SubmissionStatus::Pending { signature }),
            Outcome::Confirmed { slot } => SubmissionStatus::Confirmed { signature, slot },
            Outcome::Failed(error) => {
                self.pending = None;
                if retryable(&error, root_replaced) && self.attempts < MAX_ATTEMPTS {
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
        let proved = |instruction, tag, bound| Proved {
            instruction,
            budget: ComputeBudgetConfig::new(compute_unit_limit(tag)),
            bound,
        };
        Ok(match self {
            Self::Transfer(transfer) => {
                let proven = boxed(|| transfer.prove(client)).await?;
                let bound = proven.bound_root();
                proved(proven.instruction()?, InstructionTag::Transact, bound)
            }
            Self::Delegate(transfer) => {
                let proven = boxed(|| transfer.prove(client)).await?;
                let bound = proven.bound_root();
                proved(
                    proven.instruction()?,
                    InstructionTag::DelegateTransact,
                    bound,
                )
            }
            Self::RegisterKey(registration) => {
                let proven = boxed(|| registration.prove(client)).await?;
                proved(proven.instruction()?, InstructionTag::RegisterKey, None)
            }
            Self::Merge(operation) => {
                let mut proven = boxed(|| {
                    operation
                        .prepared
                        .clone()
                        .prove(operation.input.clone(), client)
                })
                .await?;
                if let Some(cosigner) = operation.cosigner {
                    proven = proven.with_cosigner(cosigner);
                }
                proved(proven.instruction(payer), InstructionTag::Merge, None)
            }
            Self::Deposit(deposit) => {
                let (instruction, bound) = boxed(|| deposit.prove_bound(client)).await?;
                Proved {
                    instruction,
                    budget: deposit.budget(),
                    bound,
                }
            }
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

/// A fresh proof fixes each of these, a failed proof only over an overwritten registry slot.
fn retryable(error: &TransactionError, root_replaced: bool) -> bool {
    let stale = |code| {
        code == CustomRingError::StaleKeyRegistryRoot as u32
            || (root_replaced && code == CustomRingError::ProofVerificationFailed as u32)
    };
    matches!(error, TransactionError::BlockhashNotFound) || ring_error(error).is_some_and(stale)
}

#[cfg(test)]
#[path = "tests/submission.rs"]
mod tests;
