use solana_instruction_error::InstructionError;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_error::TransactionError;
use solana_transaction_status_client_types::TransactionConfirmationStatus;
use thiserror::Error;
use zolana_client::{
    compile_message, sign_transaction, ClientError, ComputeBudgetConfig, ProverClient, Rpc,
    SolanaRpc,
};

use crate::{
    budget::TRANSACT_COMPUTE_UNIT_LIMIT, instructions::transact::ProvedWindow, CustomRingTransfer,
    TransferError, TransferProofEnvironment,
};

const MAX_ATTEMPTS: u8 = 3;
const STALE_HEAD_ROOT: u32 = 8166;
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
pub struct RingTransferSubmission<'a> {
    transfer: CustomRingTransfer<'a>,
    pending: Option<Attempt>,
    attempts: u8,
    terminal: Option<SubmissionStatus>,
}

impl<'a> RingTransferSubmission<'a> {
    pub fn new(transfer: CustomRingTransfer<'a>) -> Self {
        Self {
            transfer,
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

    /// The caller keeps the input notes reserved until a terminal result.
    pub fn send<I: Rpc>(
        &mut self,
        env: SubmissionEnvironment<'_, I>,
    ) -> Result<SubmissionStatus, SubmissionError> {
        if let Some(terminal) = &self.terminal {
            return Ok(terminal.clone());
        }
        loop {
            let mut failure = None;
            let broadcast = match &self.pending {
                Some(attempt) => attempt.broadcast(),
                None => {
                    let attempt = self.attempt(&env)?;
                    self.attempts += 1;
                    if let Err(error) = env.rpc.client().send_transaction(&attempt.transaction) {
                        // A transport error says nothing about whether the node accepted the bytes.
                        failure = error.get_transaction_error();
                    }
                    self.pending.insert(attempt).broadcast()
                }
            };
            let signature = broadcast.signature;
            let error = match failure {
                Some(error) => error,
                None => match outcome(env.rpc, broadcast)? {
                    Outcome::Unknown => return Ok(SubmissionStatus::Pending { signature }),
                    Outcome::Confirmed { slot } => {
                        let terminal = SubmissionStatus::Confirmed { signature, slot };
                        self.pending = None;
                        self.terminal = Some(terminal.clone());
                        return Ok(terminal);
                    }
                    Outcome::Failed(error) => error,
                },
            };
            let window = match broadcast.window {
                Some(window) if ring_error(&error) == Some(POLICY_PROOF_FAILED) => {
                    if env.rpc.get_slot()? / window.slots == window.index {
                        WindowState::Same
                    } else {
                        WindowState::Advanced
                    }
                }
                _ => WindowState::Same,
            };
            let retry = retryable(&error, window) && self.attempts < MAX_ATTEMPTS;
            self.pending = None;
            if !retry {
                let terminal = SubmissionStatus::Failed { signature, error };
                self.terminal = Some(terminal.clone());
                return Ok(terminal);
            }
        }
    }

    fn attempt<I: Rpc>(
        &self,
        env: &SubmissionEnvironment<'_, I>,
    ) -> Result<Attempt, SubmissionError> {
        let proven = self.transfer.clone().prove(TransferProofEnvironment {
            indexer: env.indexer,
            rpc: env.rpc,
            prover: env.prover,
        })?;
        let window = proven.window;
        let instruction = proven.instruction()?;
        let (blockhash, last_valid_block_height) = env.rpc.get_latest_blockhash()?;
        let message = compile_message(
            &env.payer.pubkey(),
            core::slice::from_ref(&instruction),
            blockhash,
            ComputeBudgetConfig::new(TRANSACT_COMPUTE_UNIT_LIMIT),
        )?;
        let mut signers: Vec<&dyn Signer> = vec![env.payer];
        signers.extend(env.signers.iter().copied());
        Ok(Attempt {
            transaction: sign_transaction(message, &signers)?,
            window,
            last_valid_block_height,
        })
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
    let [status]: [_; 1] = match response.value.try_into() {
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

// The attempt compiles a one-instruction message.
fn ring_error(error: &TransactionError) -> Option<u32> {
    match error {
        TransactionError::InstructionError(0, InstructionError::Custom(code)) => Some(*code),
        _ => None,
    }
}

fn retryable(error: &TransactionError, window: WindowState) -> bool {
    matches!(error, TransactionError::BlockhashNotFound)
        || matches!(ring_error(error), Some(STALE_HEAD_ROOT))
        || (ring_error(error) == Some(POLICY_PROOF_FAILED) && window == WindowState::Advanced)
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
        instructions::{transact::ConfidentialTransfer, types::SppProofInputUtxo},
        Data, Utxo, SOL_MINT,
    };

    fn pending(sender: &ShieldedKeypair, attempts: u8) -> RingTransferSubmission<'_> {
        let ring = CustomRing::new(Address::new_from_array([5; 32]));
        let input = SppProofInputUtxo::new(
            Utxo {
                owner: sender.signing_pubkey(),
                asset: SOL_MINT,
                amount: 10,
                blinding: random_blinding(),
                ring_program_id: Some(ring.program_id()),
                data: Data::default(),
            },
            sender,
        );
        let mut transfer = ConfidentialTransfer::new(
            sender.shielded_address().unwrap(),
            vec![input],
            sender.pubkey(),
        );
        transfer
            .send(&sender.shielded_address().unwrap(), SOL_MINT, 4)
            .unwrap();
        let transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring,
            sender,
            prepared: transfer.prepare().unwrap(),
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
}
