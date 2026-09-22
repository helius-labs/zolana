use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_instruction_error::InstructionError;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_error::TransactionError;
use solana_transaction_status_client_types::TransactionConfirmationStatus;
use solana_transaction_status_client_types::TransactionStatus;
use thiserror::Error;
use zolana_client::{
    compile_message, sign_transaction, AsyncProverClient, AsyncRpc, AsyncSolanaRpc, ClientError,
    ComputeBudgetConfig, ProverClient, Rpc, SolanaRpc,
};

use crate::{
    budget::TRANSACT_COMPUTE_UNIT_LIMIT, instructions::transact::ProvedWindow,
    AsyncCustomRingMergeProofEnvironment, AsyncTransferProofEnvironment,
    CustomRingMergeProofEnvironment, CustomRingTransfer, DelegateTransfer, EntryError,
    KeyRegistrationError, MergeError, MergeProofInput, PreparedCustomRingMerge, RegisterKey,
    RegisterSpend, TransferError, TransferProofEnvironment, REGISTER_KEY_COMPUTE_UNIT_LIMIT,
    REGISTER_SPEND_COMPUTE_UNIT_LIMIT,
};

const MAX_ATTEMPTS: u8 = 3;
const STALE_HEAD_ROOT: u32 = 8166;
const STALE_KEY_REGISTRY_ROOT: u32 = 8169;
const POLICY_PROOF_FAILED: u32 = 8101;

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

#[derive(Debug, Error)]
pub enum SubmissionError {
    #[error(transparent)]
    Prove(#[from] TransferError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Registration(Box<EntryError>),
    #[error(transparent)]
    KeyRegistration(Box<KeyRegistrationError>),
    #[error(transparent)]
    Merge(Box<MergeError>),
    #[error("submission has no signed attempt")]
    MissingAttempt,
}

impl From<EntryError> for SubmissionError {
    fn from(error: EntryError) -> Self {
        Self::Registration(Box::new(error))
    }
}
impl From<KeyRegistrationError> for SubmissionError {
    fn from(error: KeyRegistrationError) -> Self {
        Self::KeyRegistration(Box::new(error))
    }
}
impl From<MergeError> for SubmissionError {
    fn from(error: MergeError) -> Self {
        Self::Merge(Box::new(error))
    }
}

pub struct AsyncSubmissionEnvironment<'a, I: AsyncRpc> {
    pub indexer: &'a I,
    pub rpc: &'a AsyncSolanaRpc,
    pub prover: &'a AsyncProverClient,
    pub payer: &'a (dyn Signer + Sync),
    pub signers: &'a [&'a (dyn Signer + Sync)],
}

pub enum RingOperation<'a> {
    Transfer(Box<CustomRingTransfer<'a>>),
    Delegate(Box<DelegateTransfer<'a>>),
    RegisterSpend(RegisterSpend),
    RegisterKey(RegisterKey<'a>),
    Merge(Box<RingMergeOperation>),
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

impl<'a> From<CustomRingTransfer<'a>> for RingOperation<'a> {
    fn from(value: CustomRingTransfer<'a>) -> Self {
        Self::Transfer(Box::new(value))
    }
}
impl<'a> From<DelegateTransfer<'a>> for RingOperation<'a> {
    fn from(value: DelegateTransfer<'a>) -> Self {
        Self::Delegate(Box::new(value))
    }
}
impl From<RegisterSpend> for RingOperation<'_> {
    fn from(value: RegisterSpend) -> Self {
        Self::RegisterSpend(value)
    }
}
impl<'a> From<RegisterKey<'a>> for RingOperation<'a> {
    fn from(value: RegisterKey<'a>) -> Self {
        Self::RegisterKey(value)
    }
}
impl From<RingMergeOperation> for RingOperation<'_> {
    fn from(value: RingMergeOperation) -> Self {
        Self::Merge(Box::new(value))
    }
}

struct ProvedOperation {
    instruction: Instruction,
    window: Option<ProvedWindow>,
    compute_limit: u32,
}

struct AttemptSigning<'a> {
    blockhash: Hash,
    last_valid_block_height: u64,
    payer: &'a dyn Signer,
    signers: &'a [&'a dyn Signer],
}

impl ProvedOperation {
    fn sign(self, signing: AttemptSigning<'_>) -> Result<Attempt, SubmissionError> {
        let message = compile_message(
            &signing.payer.pubkey(),
            &[self.instruction],
            signing.blockhash,
            ComputeBudgetConfig::new(self.compute_limit),
        )?;
        let mut signers = vec![signing.payer];
        signers.extend_from_slice(signing.signers);
        Ok(Attempt {
            transaction: sign_transaction(message, &signers)?,
            window: self.window,
            last_valid_block_height: signing.last_valid_block_height,
        })
    }
}

pub struct SubmissionEnvironment<'a, I: Rpc> {
    pub indexer: &'a I,
    pub rpc: &'a SolanaRpc,
    pub prover: &'a ProverClient,
    pub payer: &'a dyn Signer,
    pub signers: &'a [&'a dyn Signer],
}

struct Attempt {
    transaction: VersionedTransaction,
    window: Option<ProvedWindow>,
    last_valid_block_height: u64,
}

#[derive(Clone, Copy)]
struct Broadcast {
    signature: Signature,
    window: Option<ProvedWindow>,
    last_valid_block_height: u64,
}

impl Attempt {
    fn broadcast(&self) -> Broadcast {
        Broadcast {
            signature: self.transaction.signatures[0],
            window: self.window,
            last_valid_block_height: self.last_valid_block_height,
        }
    }
}

enum Outcome {
    Unknown,
    Confirmed { slot: u64 },
    Failed(TransactionError),
}

/// Distinguishes a successful absent lookup from an unresolved transaction
/// outcome.
enum StatusObservation {
    Absent,
    Outcome(Outcome),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WindowState {
    Same,
    Advanced,
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

    /// Inputs remain reserved while the submitted signature is unresolved.
    pub fn send<I: Rpc>(
        &mut self,
        env: SubmissionEnvironment<'_, I>,
    ) -> Result<SubmissionStatus, SubmissionError> {
        if let Some(terminal) = &self.terminal {
            return Ok(terminal.clone());
        }
        loop {
            let is_new = self.pending.is_none();
            if is_new {
                let proved = self.operation.prove(&env)?;
                let (blockhash, last_valid_block_height) = env.rpc.get_latest_blockhash()?;
                self.pending = Some(proved.sign(AttemptSigning {
                    blockhash,
                    last_valid_block_height,
                    payer: env.payer,
                    signers: env.signers,
                })?);
                self.attempts += 1;
            }
            let attempt = self
                .pending
                .as_ref()
                .ok_or(SubmissionError::MissingAttempt)?;
            let broadcast = attempt.broadcast();
            let failure = if is_new {
                env.rpc
                    .client()
                    .send_transaction(&attempt.transaction)
                    .err()
                    .and_then(|error| error.get_transaction_error())
            } else {
                None
            };
            let outcome = match failure {
                Some(error) => Outcome::Failed(error),
                None => outcome(env.rpc, broadcast)?,
            };
            let window = match broadcast.window {
                Some(window) if matches!(&outcome, Outcome::Failed(error) if ring_error(error) == Some(POLICY_PROOF_FAILED)) => {
                    window_state(window, env.rpc.get_slot()?)
                }
                _ => WindowState::Same,
            };
            if let Some(status) = self.settle(Resolution {
                broadcast,
                outcome,
                window,
            }) {
                return Ok(status);
            }
        }
    }
    /// Inputs remain reserved while the submitted signature is unresolved.
    pub async fn send_async<I: AsyncRpc>(
        &mut self,
        env: AsyncSubmissionEnvironment<'_, I>,
    ) -> Result<SubmissionStatus, SubmissionError> {
        if let Some(terminal) = &self.terminal {
            return Ok(terminal.clone());
        }
        loop {
            let is_new = self.pending.is_none();
            if is_new {
                let proved = self.operation.prove_async(&env).await?;
                let (blockhash, last_valid_block_height) = env.rpc.get_latest_blockhash().await?;
                self.pending = Some(
                    proved.sign(AttemptSigning {
                        blockhash,
                        last_valid_block_height,
                        payer: env.payer,
                        signers: &env
                            .signers
                            .iter()
                            .map(|signer| *signer as &dyn Signer)
                            .collect::<Vec<_>>(),
                    })?,
                );
                self.attempts += 1;
            }
            let attempt = self
                .pending
                .as_ref()
                .ok_or(SubmissionError::MissingAttempt)?;
            let broadcast = attempt.broadcast();
            let failure = if is_new {
                env.rpc
                    .client()
                    .send_transaction(&attempt.transaction)
                    .await
                    .err()
                    .and_then(|error| error.get_transaction_error())
            } else {
                None
            };
            let outcome = match failure {
                Some(error) => Outcome::Failed(error),
                None => outcome_async(env.rpc, broadcast).await?,
            };
            let window = match broadcast.window {
                Some(window) if matches!(&outcome, Outcome::Failed(error) if ring_error(error) == Some(POLICY_PROOF_FAILED)) => {
                    window_state(window, env.rpc.get_slot().await?)
                }
                _ => WindowState::Same,
            };
            if let Some(status) = self.settle(Resolution {
                broadcast,
                outcome,
                window,
            }) {
                return Ok(status);
            }
        }
    }
    fn settle(&mut self, resolution: Resolution) -> Option<SubmissionStatus> {
        let Resolution {
            broadcast,
            outcome,
            window,
        } = resolution;
        let signature = broadcast.signature;
        let terminal = match outcome {
            Outcome::Unknown => return Some(SubmissionStatus::Pending { signature }),
            Outcome::Confirmed { slot } => SubmissionStatus::Confirmed { signature, slot },
            Outcome::Failed(error) => {
                self.pending = None;
                if retryable(&error, window) && self.attempts < MAX_ATTEMPTS {
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

pub type RingTransferSubmission<'a> = RingSubmission<'a>;

struct Resolution {
    broadcast: Broadcast,
    outcome: Outcome,
    window: WindowState,
}

fn window_state(window: ProvedWindow, slot: u64) -> WindowState {
    if slot / window.slots == window.index {
        WindowState::Same
    } else {
        WindowState::Advanced
    }
}

/// An expiry failure requires a fresh absent lookup after the blockhash
/// expires.
fn outcome(rpc: &SolanaRpc, broadcast: Broadcast) -> Result<Outcome, SubmissionError> {
    if let StatusObservation::Outcome(outcome) = observe_status(rpc, broadcast.signature) {
        return Ok(outcome);
    }
    if rpc.get_block_height()? <= broadcast.last_valid_block_height {
        return Ok(Outcome::Unknown);
    }
    // 1. The transaction can land between the first lookup and the expiry
    // observation.
    Ok(match observe_status(rpc, broadcast.signature) {
        StatusObservation::Absent => Outcome::Failed(TransactionError::BlockhashNotFound),
        StatusObservation::Outcome(outcome) => outcome,
    })
}

fn observe_status(rpc: &SolanaRpc, signature: Signature) -> StatusObservation {
    // 1. A failed status lookup cannot release the pending transaction or its
    // inputs.
    let Ok(response) = rpc
        .client()
        .get_signature_statuses_with_history(&[signature])
    else {
        return StatusObservation::Outcome(Outcome::Unknown);
    };
    decode_status(response.value)
}

fn decode_status(statuses: Vec<Option<TransactionStatus>>) -> StatusObservation {
    let [status]: [_; 1] = match statuses.try_into() {
        Ok(status) => status,
        Err(_) => return StatusObservation::Outcome(Outcome::Unknown),
    };
    let Some(status) = status else {
        return StatusObservation::Absent;
    };
    if !matches!(
        status.confirmation_status,
        Some(TransactionConfirmationStatus::Confirmed | TransactionConfirmationStatus::Finalized)
    ) {
        return StatusObservation::Outcome(Outcome::Unknown);
    }
    StatusObservation::Outcome(match status.err {
        None => Outcome::Confirmed { slot: status.slot },
        Some(error) => Outcome::Failed(error),
    })
}

async fn outcome_async(
    rpc: &AsyncSolanaRpc,
    broadcast: Broadcast,
) -> Result<Outcome, SubmissionError> {
    if let StatusObservation::Outcome(outcome) =
        observe_status_async(rpc, broadcast.signature).await
    {
        return Ok(outcome);
    }
    if rpc.get_block_height().await? <= broadcast.last_valid_block_height {
        return Ok(Outcome::Unknown);
    }
    Ok(match observe_status_async(rpc, broadcast.signature).await {
        StatusObservation::Absent => Outcome::Failed(TransactionError::BlockhashNotFound),
        StatusObservation::Outcome(outcome) => outcome,
    })
}

async fn observe_status_async(rpc: &AsyncSolanaRpc, signature: Signature) -> StatusObservation {
    match rpc
        .client()
        .get_signature_statuses_with_history(&[signature])
        .await
    {
        Ok(response) => decode_status(response.value),
        Err(_) => StatusObservation::Outcome(Outcome::Unknown),
    }
}

// The attempt compiles a one-instruction message.
fn ring_error(error: &TransactionError) -> Option<u32> {
    match error {
        TransactionError::InstructionError(0, InstructionError::Custom(code)) => Some(*code),
        _ => None,
    }
}

fn retryable(error: &TransactionError, window: WindowState) -> bool {
    matches!(error, TransactionError::BlockhashNotFound)
        || matches!(
            ring_error(error),
            Some(STALE_HEAD_ROOT | STALE_KEY_REGISTRY_ROOT)
        )
        || (ring_error(error) == Some(POLICY_PROOF_FAILED) && window == WindowState::Advanced)
}

impl RingOperation<'_> {
    fn prove<I: Rpc>(
        &self,
        env: &SubmissionEnvironment<'_, I>,
    ) -> Result<ProvedOperation, SubmissionError> {
        let proving = TransferProofEnvironment {
            indexer: env.indexer,
            rpc: env.rpc,
            prover: env.prover,
        };
        Ok(match self {
            Self::Transfer(transfer) => {
                let proven = transfer.as_ref().clone().prove(proving)?;
                ProvedOperation {
                    instruction: proven.instruction()?,
                    window: proven.window,
                    compute_limit: TRANSACT_COMPUTE_UNIT_LIMIT,
                }
            }
            Self::Delegate(transfer) => {
                let proven = transfer.as_ref().clone().prove(proving)?;
                ProvedOperation {
                    instruction: proven.instruction()?,
                    window: None,
                    compute_limit: TRANSACT_COMPUTE_UNIT_LIMIT,
                }
            }
            Self::RegisterSpend(registration) => {
                let proven = registration.prove(proving)?;
                let window = Some(proven.window);
                ProvedOperation {
                    instruction: proven.instruction()?,
                    window,
                    compute_limit: REGISTER_SPEND_COMPUTE_UNIT_LIMIT,
                }
            }
            Self::RegisterKey(registration) => {
                let proven = registration.prove(proving)?;
                ProvedOperation {
                    instruction: proven.instruction()?,
                    window: None,
                    compute_limit: REGISTER_KEY_COMPUTE_UNIT_LIMIT,
                }
            }
            Self::Merge(operation) => {
                let proven = operation.prepared.clone().prove(
                    operation.input.clone(),
                    CustomRingMergeProofEnvironment {
                        indexer: env.indexer,
                        rpc: env.rpc,
                        prover: env.prover,
                    },
                )?;
                let proven = match operation.cosigner {
                    Some(cosigner) => proven.with_cosigner(cosigner),
                    None => proven,
                };
                ProvedOperation {
                    instruction: proven.instruction(env.payer.pubkey()),
                    window: None,
                    compute_limit: TRANSACT_COMPUTE_UNIT_LIMIT,
                }
            }
        })
    }
    async fn prove_async<I: AsyncRpc>(
        &self,
        env: &AsyncSubmissionEnvironment<'_, I>,
    ) -> Result<ProvedOperation, SubmissionError> {
        let proving = AsyncTransferProofEnvironment {
            indexer: env.indexer,
            rpc: env.rpc,
            prover: env.prover,
        };
        Ok(match self {
            Self::Transfer(transfer) => {
                let proven = transfer.as_ref().clone().prove_async(proving).await?;
                ProvedOperation {
                    instruction: proven.instruction()?,
                    window: proven.window,
                    compute_limit: TRANSACT_COMPUTE_UNIT_LIMIT,
                }
            }
            Self::Delegate(transfer) => {
                let proven = transfer.as_ref().clone().prove_async(proving).await?;
                ProvedOperation {
                    instruction: proven.instruction()?,
                    window: None,
                    compute_limit: TRANSACT_COMPUTE_UNIT_LIMIT,
                }
            }
            Self::RegisterSpend(registration) => {
                let proven = registration.prove_async(proving).await?;
                let window = Some(proven.window);
                ProvedOperation {
                    instruction: proven.instruction()?,
                    window,
                    compute_limit: REGISTER_SPEND_COMPUTE_UNIT_LIMIT,
                }
            }
            Self::RegisterKey(registration) => {
                let proven = registration.prove_async(proving).await?;
                ProvedOperation {
                    instruction: proven.instruction()?,
                    window: None,
                    compute_limit: REGISTER_KEY_COMPUTE_UNIT_LIMIT,
                }
            }
            Self::Merge(operation) => {
                let proven = operation
                    .prepared
                    .clone()
                    .prove_async(
                        operation.input.clone(),
                        AsyncCustomRingMergeProofEnvironment {
                            indexer: env.indexer,
                            rpc: env.rpc,
                            prover: env.prover,
                        },
                    )
                    .await?;
                let proven = match operation.cosigner {
                    Some(cosigner) => proven.with_cosigner(cosigner),
                    None => proven,
                };
                ProvedOperation {
                    instruction: proven.instruction(env.payer.pubkey()),
                    window: None,
                    compute_limit: TRANSACT_COMPUTE_UNIT_LIMIT,
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CustomRing, CustomRingTransferInput};
    use serde_json::{json, Value};
    use solana_address::Address;
    use solana_rpc_client::{
        rpc_client::RpcClient,
        rpc_sender::{RpcSender, RpcTransportStats},
    };
    use solana_rpc_client_api::request::RpcRequest;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use zolana_keypair::{random_blinding, ShieldedKeypair};
    use zolana_transaction::{
        instructions::transact::ConfidentialTransaction, utxo::SppProofInputUtxo, Data, Mint, Utxo,
        SOL_MINT,
    };

    fn pending(sender: &ShieldedKeypair, attempts: u8) -> RingTransferSubmission<'_> {
        let ring = CustomRing::new(Address::new_from_array([5; 32]));
        let input = zolana_test_utils::utxo::wallet(
            Utxo {
                owner: sender.signing_pubkey(),
                asset: Mint::SOL,
                amount: 10,
                blinding: random_blinding(),
                ring_program_id: Some(ring.program_id()),
                data: Data::default(),
            },
            &sender.nullifier_key,
            0,
            0,
            None,
            None,
        )
        .unwrap();
        let mut transaction = ConfidentialTransaction::new(vec![input], sender.pubkey()).unwrap();
        transaction
            .transfer_sol(&sender.shielded_address().unwrap(), 4)
            .unwrap();
        let transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring,
            sender,
            nullifier_key: Some(&sender.nullifier_key),
            transaction,
        });
        let message = compile_message(
            &sender.pubkey(),
            &[],
            Default::default(),
            ComputeBudgetConfig::new(1_400_000),
        )
        .unwrap();
        let transaction = sign_transaction(message, &[sender]).unwrap();
        let mut submission = RingTransferSubmission::new(transfer);
        submission.pending = Some(Attempt {
            transaction,
            window: None,
            last_valid_block_height: 20,
        });
        submission.attempts = attempts;
        submission
    }

    fn rpc(status: Value, block_height: u64) -> SolanaRpc {
        SolanaRpc::with_client(RpcClient::new_mock_with_mocks(
            "succeeds",
            [
                (
                    RpcRequest::GetSignatureStatuses,
                    json!({"context": {"slot": 9}, "value": [status]}),
                ),
                (RpcRequest::GetBlockHeight, json!(block_height)),
            ]
            .into_iter()
            .collect(),
        ))
    }

    fn failed(index: u8, code: u32) -> Value {
        let error = json!({"InstructionError": [index, {"Custom": code}]});
        json!({"slot": 9, "confirmations": 1, "confirmationStatus": "confirmed", "err": error, "status": {"Err": error}})
    }

    fn send(
        submission: &mut RingTransferSubmission<'_>,
        rpc: &SolanaRpc,
        payer: &ShieldedKeypair,
    ) -> SubmissionStatus {
        submission
            .send(SubmissionEnvironment {
                indexer: rpc,
                rpc,
                prover: &ProverClient::local(),
                payer,
                signers: &[],
            })
            .unwrap()
    }

    /// Enforces the lookup, expiry, then fresh lookup order for one pending
    /// signature.
    struct ExpiryObservation {
        requests: Arc<AtomicUsize>,
        statuses_after_expiry: Option<Value>,
    }

    impl ExpiryObservation {
        fn into_rpc(self) -> SolanaRpc {
            SolanaRpc::with_client(RpcClient::new_sender(self, Default::default()))
        }
    }

    #[async_trait::async_trait]
    impl RpcSender for ExpiryObservation {
        async fn send(
            &self,
            request: RpcRequest,
            _params: Value,
        ) -> solana_rpc_client_api::client_error::Result<Value> {
            match (self.requests.fetch_add(1, Ordering::Relaxed), request) {
                (0, RpcRequest::GetSignatureStatuses) => {
                    Ok(json!({"context": {"slot": 20}, "value": [null]}))
                }
                (1, RpcRequest::GetBlockHeight) => Ok(json!(21)),
                (2, RpcRequest::GetSignatureStatuses) => match &self.statuses_after_expiry {
                    Some(statuses) => Ok(json!({"context": {"slot": 21}, "value": statuses})),
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "post-expiry status connection reset",
                    )
                    .into()),
                },
                other => panic!("unexpected RPC sequence: {other:?}"),
            }
        }

        fn get_transport_stats(&self) -> RpcTransportStats {
            RpcTransportStats::default()
        }

        fn url(&self) -> String {
            "mock-expiry-observation".to_owned()
        }
    }

    #[test]
    fn unknown_outcome_only_polls_the_original_signature() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        let mut submission = pending(&sender, 1);
        let transaction = submission.pending_transaction().unwrap().clone();
        for _ in 0..2 {
            let rpc = rpc(Value::Null, 10);
            assert_eq!(
                send(&mut submission, &rpc, &sender),
                SubmissionStatus::Pending {
                    signature: transaction.signatures[0]
                }
            );
            assert_eq!(submission.attempts(), 1);
            assert_eq!(submission.pending_transaction(), Some(&transaction));
        }
    }

    #[test]
    fn a_status_transport_failure_preserves_the_pending_attempt_past_expiry() {
        /// Rejects status lookups and records whether an unsafe expiry check
        /// follows.
        struct StatusFailure {
            status_calls: Arc<AtomicUsize>,
            height_calls: Arc<AtomicUsize>,
            block_height: u64,
        }

        #[async_trait::async_trait]
        impl RpcSender for StatusFailure {
            async fn send(
                &self,
                request: RpcRequest,
                _params: Value,
            ) -> solana_rpc_client_api::client_error::Result<Value> {
                match request {
                    RpcRequest::GetSignatureStatuses => {
                        self.status_calls.fetch_add(1, Ordering::Relaxed);
                        Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionReset,
                            "status connection reset",
                        )
                        .into())
                    }
                    RpcRequest::GetBlockHeight => {
                        self.height_calls.fetch_add(1, Ordering::Relaxed);
                        Ok(json!(self.block_height))
                    }
                    other => panic!("unexpected RPC request: {other:?}"),
                }
            }

            fn get_transport_stats(&self) -> RpcTransportStats {
                RpcTransportStats::default()
            }

            fn url(&self) -> String {
                "mock-status-failure".to_owned()
            }
        }

        let sender = ShieldedKeypair::new_ed25519().unwrap();
        for attempts in [1, MAX_ATTEMPTS] {
            for block_height in [10, 21] {
                let mut submission = pending(&sender, attempts);
                let transaction = submission.pending_transaction().unwrap().clone();
                let status_calls = Arc::new(AtomicUsize::new(0));
                let height_calls = Arc::new(AtomicUsize::new(0));
                let failing = SolanaRpc::with_client(RpcClient::new_sender(
                    StatusFailure {
                        status_calls: status_calls.clone(),
                        height_calls: height_calls.clone(),
                        block_height,
                    },
                    Default::default(),
                ));
                for _ in 0..2 {
                    assert_eq!(
                        send(&mut submission, &failing, &sender),
                        SubmissionStatus::Pending {
                            signature: transaction.signatures[0]
                        }
                    );
                    assert_eq!(submission.attempts(), attempts);
                    assert_eq!(submission.pending_transaction(), Some(&transaction));
                }
                assert_eq!(status_calls.load(Ordering::Relaxed), 2);
                assert_eq!(height_calls.load(Ordering::Relaxed), 0);
                let confirmed = rpc(
                    json!({"slot": 9, "confirmations": 1, "confirmationStatus": "confirmed", "err": null, "status": {"Ok": null}}),
                    block_height,
                );
                assert_eq!(
                    send(&mut submission, &confirmed, &sender),
                    SubmissionStatus::Confirmed {
                        signature: transaction.signatures[0],
                        slot: 9,
                    }
                );
            }
        }
    }

    #[test]
    fn malformed_status_counts_preserve_the_pending_attempt_past_expiry() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        for statuses in [
            json!([]),
            json!([null, null]),
            json!([
                {"slot": 9, "confirmations": 1, "confirmationStatus": "confirmed", "err": null, "status": {"Ok": null}},
                null
            ]),
        ] {
            let mut submission = pending(&sender, MAX_ATTEMPTS);
            let transaction = submission.pending_transaction().unwrap().clone();
            let rpc = SolanaRpc::with_client(RpcClient::new_mock_with_mocks(
                "succeeds",
                [
                    (
                        RpcRequest::GetSignatureStatuses,
                        json!({"context": {"slot": 9}, "value": statuses}),
                    ),
                    (RpcRequest::GetBlockHeight, json!(21)),
                ]
                .into_iter()
                .collect(),
            ));
            assert_eq!(
                send(&mut submission, &rpc, &sender),
                SubmissionStatus::Pending {
                    signature: transaction.signatures[0],
                }
            );
            assert_eq!(submission.attempts(), MAX_ATTEMPTS);
            assert_eq!(submission.pending_transaction(), Some(&transaction));
        }
    }

    #[test]
    fn an_expired_blockhash_fails_the_last_attempt() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        let mut submission = pending(&sender, MAX_ATTEMPTS);
        let signature = submission.pending_transaction().unwrap().signatures[0];
        let requests = Arc::new(AtomicUsize::new(0));
        let rpc = ExpiryObservation {
            requests: requests.clone(),
            statuses_after_expiry: Some(json!([null])),
        }
        .into_rpc();
        assert_eq!(
            send(&mut submission, &rpc, &sender),
            SubmissionStatus::Failed {
                signature,
                error: TransactionError::BlockhashNotFound
            }
        );
        assert_eq!(requests.load(Ordering::Relaxed), 3);
        assert!(submission.pending_transaction().is_none());
    }

    #[test]
    fn a_transaction_landing_during_the_expiry_check_confirms_the_original_signature() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        let mut submission = pending(&sender, 1);
        let signature = submission.pending_transaction().unwrap().signatures[0];
        let requests = Arc::new(AtomicUsize::new(0));
        let rpc = ExpiryObservation {
            requests: requests.clone(),
            statuses_after_expiry: Some(json!([
                {"slot": 20, "confirmations": 1, "confirmationStatus": "confirmed", "err": null, "status": {"Ok": null}}
            ])),
        }
        .into_rpc();
        for _ in 0..2 {
            assert_eq!(
                send(&mut submission, &rpc, &sender),
                SubmissionStatus::Confirmed {
                    signature,
                    slot: 20
                }
            );
        }
        assert_eq!(requests.load(Ordering::Relaxed), 3);
        assert_eq!(submission.attempts(), 1);
        assert!(submission.pending_transaction().is_none());
    }

    #[test]
    fn a_failed_transaction_landing_during_the_expiry_check_keeps_its_actual_error() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        let mut submission = pending(&sender, 1);
        let signature = submission.pending_transaction().unwrap().signatures[0];
        let requests = Arc::new(AtomicUsize::new(0));
        let rpc = ExpiryObservation {
            requests: requests.clone(),
            statuses_after_expiry: Some(json!([failed(1, 8145)])),
        }
        .into_rpc();
        assert_eq!(
            send(&mut submission, &rpc, &sender),
            SubmissionStatus::Failed {
                signature,
                error: TransactionError::InstructionError(1, InstructionError::Custom(8145)),
            }
        );
        assert_eq!(requests.load(Ordering::Relaxed), 3);
        assert_eq!(submission.attempts(), 1);
        assert!(submission.pending_transaction().is_none());
    }

    #[test]
    fn an_unresolved_post_expiry_lookup_preserves_the_original_attempt_until_confirmation() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        for statuses_after_expiry in [
            None,
            Some(json!([])),
            Some(json!([null, null])),
            Some(json!([
                {"slot": 20, "confirmations": 1, "confirmationStatus": "confirmed", "err": null, "status": {"Ok": null}},
                null
            ])),
            Some(json!([
                {"slot": 20, "confirmations": 0, "confirmationStatus": "processed", "err": null, "status": {"Ok": null}}
            ])),
        ] {
            for attempts in [1, MAX_ATTEMPTS] {
                let mut submission = pending(&sender, attempts);
                let transaction = submission.pending_transaction().unwrap().clone();
                let signature = transaction.signatures[0];
                let requests = Arc::new(AtomicUsize::new(0));
                let uncertain = ExpiryObservation {
                    requests: requests.clone(),
                    statuses_after_expiry: statuses_after_expiry.clone(),
                }
                .into_rpc();
                assert_eq!(
                    send(&mut submission, &uncertain, &sender),
                    SubmissionStatus::Pending { signature }
                );
                assert_eq!(requests.load(Ordering::Relaxed), 3);
                assert_eq!(submission.attempts(), attempts);
                assert_eq!(submission.pending_transaction(), Some(&transaction));
                let confirmed = rpc(
                    json!({"slot": 20, "confirmations": 1, "confirmationStatus": "confirmed", "err": null, "status": {"Ok": null}}),
                    21,
                );
                assert_eq!(
                    send(&mut submission, &confirmed, &sender),
                    SubmissionStatus::Confirmed {
                        signature,
                        slot: 20
                    }
                );
                assert_eq!(submission.attempts(), attempts);
                assert!(submission.pending_transaction().is_none());
            }
        }
    }

    #[test]
    fn confirmation_finishes_once_and_releases_the_pending_attempt() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        let mut submission = pending(&sender, 1);
        let signature = submission.pending_transaction().unwrap().signatures[0];
        let rpc = rpc(
            json!({"slot": 9, "confirmations": 1, "confirmationStatus": "confirmed", "err": null, "status": {"Ok": null}}),
            10,
        );
        for _ in 0..2 {
            assert_eq!(
                send(&mut submission, &rpc, &sender),
                SubmissionStatus::Confirmed { signature, slot: 9 }
            );
            assert_eq!(submission.attempts(), 1);
            assert!(submission.pending_transaction().is_none());
        }
    }

    #[test]
    fn unrelated_errors_and_the_third_failed_attempt_never_reprove() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        for (attempts, index, code) in [
            (1, 1, STALE_HEAD_ROOT),
            (1, 0, 8145),
            (3, 0, STALE_HEAD_ROOT),
        ] {
            let mut submission = pending(&sender, attempts);
            let signature = submission.pending_transaction().unwrap().signatures[0];
            let rpc = rpc(failed(index, code), 10);
            assert_eq!(
                send(&mut submission, &rpc, &sender),
                SubmissionStatus::Failed {
                    signature,
                    error: TransactionError::InstructionError(
                        index,
                        InstructionError::Custom(code)
                    )
                }
            );
            assert_eq!(submission.attempts(), attempts);
            assert!(submission.pending_transaction().is_none());
        }
    }

    #[test]
    fn only_the_bound_ring_failure_can_retry() {
        let error =
            |index, code| TransactionError::InstructionError(index, InstructionError::Custom(code));
        assert!(retryable(&error(0, STALE_HEAD_ROOT), WindowState::Same));
        assert!(!retryable(&error(1, STALE_HEAD_ROOT), WindowState::Same));
        assert!(retryable(
            &error(0, STALE_KEY_REGISTRY_ROOT),
            WindowState::Same
        ));
        assert!(!retryable(
            &error(1, STALE_KEY_REGISTRY_ROOT),
            WindowState::Same
        ));
        assert!(!retryable(
            &error(0, POLICY_PROOF_FAILED),
            WindowState::Same
        ));
        assert!(retryable(
            &error(0, POLICY_PROOF_FAILED),
            WindowState::Advanced
        ));
        assert!(!retryable(&error(0, 8145), WindowState::Advanced));
        assert!(!retryable(
            &TransactionError::AccountInUse,
            WindowState::Advanced
        ));
        assert!(retryable(
            &TransactionError::BlockhashNotFound,
            WindowState::Same
        ));
    }
    fn operations(sender: &ShieldedKeypair) -> Vec<RingOperation<'_>> {
        let ring = CustomRing::new(Address::new_from_array([5; 32]));
        let wallets: Vec<_> = [3, 5]
            .into_iter()
            .enumerate()
            .map(|(index, amount)| {
                zolana_test_utils::utxo::wallet(
                    Utxo {
                        owner: sender.signing_pubkey(),
                        asset: Mint::SOL,
                        amount,
                        blinding: random_blinding(),
                        ring_program_id: Some(ring.program_id()),
                        data: Data::default(),
                    },
                    &sender.nullifier_key,
                    0,
                    index as u64,
                    None,
                    None,
                )
                .unwrap()
            })
            .collect();
        let inputs = wallets
            .iter()
            .map(SppProofInputUtxo::from)
            .collect::<Vec<_>>();
        let merge = crate::CustomRingMerge::new(ring, wallets, None)
            .unwrap()
            .encrypt(sender)
            .unwrap();
        vec![
            pending(sender, 1).operation,
            DelegateTransfer::new(crate::DelegateTransferInput {
                ring,
                delegate: sender.pubkey(),
                payer: sender.pubkey(),
                inputs,
                outputs: vec![crate::DelegateOutput {
                    recipient: sender.shielded_address().unwrap(),
                    asset: SOL_MINT,
                    amount: 8,
                }],
            })
            .into(),
            RegisterSpend {
                ring,
                payer: sender.pubkey(),
            }
            .into(),
            RegisterKey {
                ring,
                member: sender,
            }
            .into(),
            RingMergeOperation::new(
                merge,
                MergeProofInput {
                    nullifier_key: sender.nullifier_key.clone(),
                    input_tree: Address::new_unique(),
                    output_tree: Address::new_unique(),
                },
            )
            .into(),
        ]
    }

    #[test]
    fn every_operation_keeps_the_signed_attempt_until_confirmation() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        for operation in operations(&sender) {
            let mut submission = pending(&sender, 1);
            submission.operation = operation;
            let transaction = submission.pending_transaction().unwrap().clone();
            let signature = transaction.signatures[0];
            assert_eq!(
                send(&mut submission, &rpc(Value::Null, 10), &sender),
                SubmissionStatus::Pending { signature }
            );
            assert_eq!(submission.pending_transaction(), Some(&transaction));
            assert_eq!(submission.attempts(), 1);
        }
    }

    async fn send_async(
        submission: &mut RingSubmission<'_>,
        rpc: &AsyncSolanaRpc,
        payer: &ShieldedKeypair,
    ) -> SubmissionStatus {
        let prover = AsyncProverClient::local();
        let future = submission.send_async(AsyncSubmissionEnvironment {
            indexer: rpc,
            rpc,
            prover: &prover,
            payer,
            signers: &[],
        });
        fn requires_send<T: Send>(value: T) -> T {
            value
        }
        requires_send(future).await.unwrap()
    }

    #[tokio::test]
    async fn async_operations_keep_the_same_signature_across_unknown_results() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        for operation in operations(&sender) {
            let mut submission = pending(&sender, 1);
            submission.operation = operation;
            let transaction = submission.pending_transaction().unwrap().clone();
            let signature = transaction.signatures[0];
            let rpc = AsyncSolanaRpc::with_client(
                solana_rpc_client::nonblocking::rpc_client::RpcClient::new_mock_with_mocks(
                    "succeeds".into(),
                    [
                        (
                            RpcRequest::GetSignatureStatuses,
                            json!({"context": {"slot": 9}, "value": [null]}),
                        ),
                        (RpcRequest::GetBlockHeight, json!(10)),
                    ]
                    .into_iter()
                    .collect(),
                ),
            );
            assert_eq!(
                send_async(&mut submission, &rpc, &sender).await,
                SubmissionStatus::Pending { signature }
            );
            assert_eq!(submission.pending_transaction(), Some(&transaction));
            assert_eq!(submission.attempts(), 1);
        }
    }

    #[tokio::test]
    async fn async_expiry_requires_a_fresh_resolved_status() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        for statuses_after_expiry in [
            None,
            Some(json!([])),
            Some(json!([null, null])),
            Some(json!([
                {"slot": 20, "confirmations": 0, "confirmationStatus": "processed", "err": null, "status": {"Ok": null}}
            ])),
        ] {
            let mut submission = pending(&sender, MAX_ATTEMPTS);
            let transaction = submission.pending_transaction().unwrap().clone();
            let signature = transaction.signatures[0];
            let requests = Arc::new(AtomicUsize::new(0));
            let rpc = AsyncSolanaRpc::with_client(
                solana_rpc_client::nonblocking::rpc_client::RpcClient::new_sender(
                    ExpiryObservation {
                        requests: requests.clone(),
                        statuses_after_expiry,
                    },
                    Default::default(),
                ),
            );
            assert_eq!(
                send_async(&mut submission, &rpc, &sender).await,
                SubmissionStatus::Pending { signature }
            );
            assert_eq!(submission.pending_transaction(), Some(&transaction));
            assert_eq!(requests.load(Ordering::Relaxed), 3);
        }
        let mut submission = pending(&sender, 1);
        let signature = submission.pending_transaction().unwrap().signatures[0];
        let requests = Arc::new(AtomicUsize::new(0));
        let rpc = AsyncSolanaRpc::with_client(
            solana_rpc_client::nonblocking::rpc_client::RpcClient::new_sender(
                ExpiryObservation {
                    requests: requests.clone(),
                    statuses_after_expiry: Some(json!([
                        {"slot": 20, "confirmations": 1, "confirmationStatus": "confirmed", "err": null, "status": {"Ok": null}}
                    ])),
                },
                Default::default(),
            ),
        );
        for _ in 0..2 {
            assert_eq!(
                send_async(&mut submission, &rpc, &sender).await,
                SubmissionStatus::Confirmed {
                    signature,
                    slot: 20
                }
            );
        }
        assert_eq!(requests.load(Ordering::Relaxed), 3);
        assert_eq!(submission.attempts(), 1);
    }

    #[test]
    fn retry_decisions_preserve_unknown_attempts_and_stop_at_the_limit() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        for code in [
            STALE_HEAD_ROOT,
            STALE_KEY_REGISTRY_ROOT,
            POLICY_PROOF_FAILED,
        ] {
            let mut submission = pending(&sender, 1);
            let broadcast = submission.pending.as_ref().unwrap().broadcast();
            let transaction = submission.pending_transaction().unwrap().clone();
            assert_eq!(
                submission.settle(Resolution {
                    broadcast,
                    outcome: Outcome::Unknown,
                    window: WindowState::Advanced
                }),
                Some(SubmissionStatus::Pending {
                    signature: broadcast.signature
                })
            );
            assert_eq!(submission.pending_transaction(), Some(&transaction));
            let failure = || {
                Outcome::Failed(TransactionError::InstructionError(
                    0,
                    InstructionError::Custom(code),
                ))
            };
            assert!(submission
                .settle(Resolution {
                    broadcast,
                    outcome: failure(),
                    window: WindowState::Advanced
                })
                .is_none());
            assert!(submission.pending_transaction().is_none());
            submission.attempts = MAX_ATTEMPTS;
            assert!(matches!(
                submission.settle(Resolution {
                    broadcast,
                    outcome: failure(),
                    window: WindowState::Advanced
                }),
                Some(SubmissionStatus::Failed { .. })
            ));
        }
    }
}
