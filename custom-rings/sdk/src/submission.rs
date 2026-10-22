//! Sends a ring operation and proves it again when the chain moved under its proof.

use std::time::Duration;

use custom_ring_interface::{
    compute_unit_limit, stream::tag_epoch, CustomRingError, InstructionTag, MemberRegistry,
};
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
    heap::boxed, records::BoundQueue, trees::BoundAnchor, AnonymousTransfer, AuthorityListWrite,
    CustomRing, CustomRingTransfer, DelegateTransfer, PendingFirstContact, PreparedRingDeposit,
    RecordApplication, RegisterKey, RingError, RingMergeOperation,
};

#[cfg(test)]
#[path = "tests/submission.rs"]
mod tests;

pub(crate) fn check_transaction_size(
    payer: &Address,
    instruction: &Instruction,
    budget: ComputeBudgetConfig,
) -> Result<(), RingError> {
    let size = zolana_client::transaction_size(payer, core::slice::from_ref(instruction), budget)?;
    if size.bytes > solana_message::v1::MAX_TRANSACTION_SIZE {
        return Err(RingError::TransactionTooLarge {
            bytes: size.bytes,
            limit: solana_message::v1::MAX_TRANSACTION_SIZE,
        });
    }
    if size.addresses > usize::from(solana_message::v1::MAX_ADDRESSES) {
        return Err(RingError::TooManyAddresses {
            addresses: size.addresses,
            limit: usize::from(solana_message::v1::MAX_ADDRESSES),
        });
    }
    Ok(())
}

const MAX_ATTEMPTS: u8 = 3;
const PENDING_POLL: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmissionStatus {
    Settled(SettledSubmission),
    Pending { signature: Signature },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettledSubmission {
    Confirmed {
        signature: Signature,
        slot: u64,
        /// Those of the attempt that landed.
        first_contacts: Vec<PendingFirstContact>,
    },
    Failed {
        signature: Signature,
        error: TransactionError,
    },
}

pub enum RingOperation<'a> {
    Transfer(Box<CustomRingTransfer<'a>>),
    Anonymous(Box<AnonymousTransfer<'a>>),
    Delegate(Box<DelegateTransfer<'a>>),
    RegisterKey(Box<RegisterKey<'a>>),
    /// One batch, [`AuthorityListWrite::batches`] splits a larger write.
    AuthorityListWrite(Box<AuthorityListWrite>),
    RecordApplication(RecordApplication),
    Merge(Box<RingMergeOperation>),
    Deposit(Box<PreparedRingDeposit>),
    /// A built instruction, sent as is, its budget from its tag.
    Instruction(Instruction),
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
    Anonymous(AnonymousTransfer<'a>) => Box::new,
    Delegate(DelegateTransfer<'a>) => Box::new,
    RegisterKey(RegisterKey<'a>) => Box::new,
    AuthorityListWrite(AuthorityListWrite) => Box::new,
    RecordApplication(RecordApplication) => core::convert::identity,
    Merge(RingMergeOperation) => Box::new,
    Deposit(PreparedRingDeposit) => Box::new,
    Instruction(Instruction) => core::convert::identity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BoundRoot {
    pub ring: CustomRing,
    /// The history slot the statement names.
    pub index: u8,
    pub root: [u8; 32],
}

impl BoundRoot {
    pub(crate) fn registry(ring: CustomRing, index: u8, root: [u8; 32]) -> Self {
        Self { ring, index, root }
    }

    /// The newest root, never below the floor when read.
    pub(crate) fn current(ring: CustomRing, registry: &MemberRegistry) -> Self {
        Self::registry(ring, registry.history_cursor, registry.current_root())
    }

    pub(crate) async fn newest(
        ring: CustomRing,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Self, RingError> {
        Ok(Self::current(ring, &*ring.require_registry(rpc).await?))
    }

    /// `true` once the history wraps over the slot, the program then reads another root.
    async fn replaced(self, client: &(impl AsyncRpc + ?Sized)) -> Result<bool, RingError> {
        let registry = self.ring.require_registry(client).await?;
        Ok(registry.history[usize::from(self.index)].root != self.root)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BoundPolicy {
    pub ring: CustomRing,
    pub hash: [u8; 32],
}

/// Every value a proof binds that the chain can move before it lands.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct BoundState {
    pub roots: Vec<BoundRoot>,
    pub policy: Option<BoundPolicy>,
    pub anchor: Option<BoundAnchor>,
    pub queue: Option<BoundQueue>,
    pub epoch: Option<u64>,
}

impl BoundState {
    /// A failed verification counts only once a bound value moved.
    async fn reproof_fixes(
        &self,
        error: &TransactionError,
        client: &(impl AsyncRpc + ?Sized),
    ) -> Result<bool, RingError> {
        let Some(code) = ring_error(error) else {
            return Ok(matches!(error, TransactionError::BlockhashNotFound));
        };
        if code == CustomRingError::ProofVerificationFailed as u32 {
            return self.moved(client).await;
        }
        Ok([
            CustomRingError::RootBelowFloor,
            CustomRingError::CuratorRootStale,
            CustomRingError::RootIndexEmpty,
            CustomRingError::AuthorityBatchTooLarge,
        ]
        .into_iter()
        .any(|stale| code == stale as u32))
    }

    /// `true` once a bound value moved or the epoch the proof binds passed.
    async fn moved(&self, client: &(impl AsyncRpc + ?Sized)) -> Result<bool, RingError> {
        for root in &self.roots {
            if root.replaced(client).await? {
                return Ok(true);
            }
        }
        if let Some(policy) = self.policy {
            if policy.ring.require_registry(client).await?.policy_hash != policy.hash {
                return Ok(true);
            }
        }
        if let Some(anchor) = self.anchor {
            if !anchor.holds(client).await? {
                return Ok(true);
            }
        }
        if let Some(queue) = &self.queue {
            let registry = queue.ring.require_registry(client).await?;
            let current = queue.ring.require_queue(client).await?;
            if current.tail() != queue.tail
                || current.chain_tail() != queue.chain_tail
                || registry.current_root() != queue.root
            {
                return Ok(true);
            }
        }
        if let Some(epoch) = self.epoch {
            if tag_epoch(client.get_slot().await?) > epoch {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

struct Proved {
    instruction: Instruction,
    budget: ComputeBudgetConfig,
    bound: BoundState,
    first_contacts: Vec<PendingFirstContact>,
}

impl Proved {
    fn with_first_contacts(self, first_contacts: Vec<PendingFirstContact>) -> Self {
        Self {
            first_contacts,
            ..self
        }
    }
}

struct Attempt {
    transaction: VersionedTransaction,
    bound: BoundState,
    first_contacts: Vec<PendingFirstContact>,
    last_valid_block_height: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Unknown,
    Confirmed {
        slot: u64,
    },
    Failed(TransactionError),
    /// A fresh proof fixes the failure.
    Stale(TransactionError),
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
        if let Some(terminal) = &self.terminal {
            return Ok(terminal.clone());
        }
        loop {
            let (attempt, failure) = match self.pending.take() {
                Some(attempt) => (attempt, None),
                None => {
                    let public: Vec<Address> = core::iter::once(payer.pubkey())
                        .chain(signers.iter().map(|signer| signer.pubkey()))
                        .collect();
                    self.operation.check_public_signers(client, &public).await?;
                    let proved = boxed(|| self.operation.prove(client, payer.pubkey())).await?;
                    check_transaction_size(&payer.pubkey(), &proved.instruction, proved.budget)?;
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
                    let attempt = Attempt {
                        transaction,
                        bound: proved.bound,
                        first_contacts: proved.first_contacts,
                        last_valid_block_height,
                    };
                    (attempt, failure)
                }
            };
            let attempt = self.pending.insert(attempt);
            let signature = attempt.transaction.signatures[0];
            let outcome = match failure {
                Some(error) => Outcome::Failed(error),
                None => outcome(client, signature, attempt.last_valid_block_height).await?,
            };
            let outcome = match outcome {
                Outcome::Failed(error) if attempt.bound.reproof_fixes(&error, client).await? => {
                    Outcome::Stale(error)
                }
                outcome => outcome,
            };
            if let Some(status) = self.settle(signature, outcome) {
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
                SubmissionStatus::Settled(settled) => return Ok(settled),
                SubmissionStatus::Pending { .. } => tokio::time::sleep(PENDING_POLL).await,
            }
        }
    }

    /// `None` proves again after a stale failure below the attempt limit.
    fn settle(&mut self, signature: Signature, outcome: Outcome) -> Option<SubmissionStatus> {
        let settled = match outcome {
            Outcome::Unknown => return Some(SubmissionStatus::Pending { signature }),
            Outcome::Confirmed { slot } => SettledSubmission::Confirmed {
                signature,
                slot,
                first_contacts: self
                    .pending
                    .take()
                    .map(|attempt| attempt.first_contacts)
                    .unwrap_or_default(),
            },
            Outcome::Failed(error) => {
                self.pending = None;
                SettledSubmission::Failed { signature, error }
            }
            Outcome::Stale(error) => {
                self.pending = None;
                if self.attempts < MAX_ATTEMPTS {
                    return None;
                }
                SettledSubmission::Failed { signature, error }
            }
        };
        let terminal = SubmissionStatus::Settled(settled);
        self.terminal = Some(terminal.clone());
        Some(terminal)
    }
}

impl RingOperation<'_> {
    async fn check_public_signers(
        &self,
        client: &(impl AsyncRpc + ?Sized),
        signers: &[Address],
    ) -> Result<(), RingError> {
        let signers = signers.iter().copied();
        match self {
            Self::Anonymous(transfer) => transfer.check_public_signers(signers),
            Self::Merge(operation) => {
                let config = operation.prepared.ring().require_config(client).await?;
                operation.prepared.check_public_signers(signers, &config)
            }
            Self::Deposit(deposit) => deposit.check_public_signers(signers),
            Self::Transfer(_)
            | Self::Delegate(_)
            | Self::RegisterKey(_)
            | Self::AuthorityListWrite(_)
            | Self::RecordApplication(_)
            | Self::Instruction(_) => Ok(()),
        }
    }

    async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
        payer: Address,
    ) -> Result<Proved, RingError> {
        let proved = |instruction, tag, bound| Proved {
            instruction,
            budget: ComputeBudgetConfig::new(compute_unit_limit(tag)),
            bound,
            first_contacts: Vec::new(),
        };
        Ok(match self {
            Self::Transfer(transfer) => {
                let proven = boxed(|| transfer.prove(client)).await?;
                let instruction = proven.instruction_at(client.get_slot().await?)?;
                proved(instruction, InstructionTag::Transact, proven.bound())
            }
            Self::Anonymous(transfer) => {
                let proven = boxed(|| transfer.prove(client)).await?;
                let instruction = proven.instruction_at(client.get_slot().await?)?;
                proved(instruction, InstructionTag::Transact, proven.bound())
                    .with_first_contacts(proven.first_contacts)
            }
            Self::Delegate(transfer) => {
                let proven = boxed(|| transfer.prove(client)).await?;
                let instruction = proven.instruction_at(client.get_slot().await?)?;
                proved(
                    instruction,
                    InstructionTag::DelegateTransact,
                    proven.bound(),
                )
            }
            Self::RegisterKey(registration) => {
                let proven = boxed(|| registration.prove(client)).await?;
                proved(
                    proven.instruction,
                    InstructionTag::RegisterKey,
                    BoundState::default(),
                )
            }
            Self::AuthorityListWrite(write) => {
                let proven = boxed(|| write.prove(client)).await?;
                proved(
                    proven.instruction,
                    InstructionTag::AuthorityWriteRecords,
                    BoundState {
                        queue: Some(proven.bound),
                        ..BoundState::default()
                    },
                )
            }
            Self::RecordApplication(application) => {
                let proven = boxed(|| application.prove(client))
                    .await?
                    .ok_or(RingError::ApplicationNotDue)?;
                proved(
                    proven.instruction,
                    InstructionTag::ApplyRecords,
                    BoundState {
                        queue: Some(proven.bound),
                        ..BoundState::default()
                    },
                )
            }
            Self::Merge(operation) => {
                let budget = ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::Merge));
                let config = operation.prepared.ring().require_config(client).await?;
                check_transaction_size(
                    &payer,
                    &operation.preview_instruction(payer, &config)?,
                    budget,
                )?;
                let proven = boxed(|| {
                    operation
                        .prepared
                        .clone()
                        .prove(operation.input.clone(), client)
                })
                .await?;
                proved(
                    proven.instruction(payer)?,
                    InstructionTag::Merge,
                    BoundState {
                        roots: proven.bound_root().into_iter().collect(),
                        ..BoundState::default()
                    },
                )
            }
            Self::Deposit(deposit) => {
                let proven = boxed(|| deposit.prove_bound(client)).await?;
                proved(
                    proven.instruction,
                    InstructionTag::AuditedDeposit,
                    BoundState {
                        roots: proven.root.into_iter().collect(),
                        ..BoundState::default()
                    },
                )
            }
            Self::Instruction(instruction) => {
                let tag = instruction
                    .data
                    .first()
                    .and_then(|tag| InstructionTag::try_from(*tag).ok())
                    .ok_or(CustomRingError::InvalidInstructionData)?;
                proved(instruction.clone(), tag, BoundState::default())
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
