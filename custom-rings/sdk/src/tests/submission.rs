//! A child of `submission`, the pending attempt and its settlement are private to it.

use std::{
    collections::VecDeque,
    num::NonZeroU64,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use async_trait::async_trait;
use serde_json::{json, Value};
use solana_account::Account;
use solana_rpc_client::{
    nonblocking::rpc_client::RpcClient,
    rpc_sender::{RpcSender, RpcTransportStats},
};
use solana_rpc_client_api::request::RpcRequest;
use zolana_client::{AsyncProverClient, AsyncSolanaRpc, ClientError};
use zolana_keypair::ShieldedKeypair;
use zolana_ring_policy::{Member, RuleTable, VelocityRow};
use zolana_transaction::{instructions::transact::ConfidentialTransaction, SOL_MINT};

use super::*;
use crate::{
    tests::support::{account, no_witnesses, note, pinned, ring},
    CustomRing, CustomRingMerge, CustomRingTransferInput, DelegateOutput, DelegateTransferInput,
    PoolTree,
};

const STALE_ROOT: u32 = CustomRingError::StaleKeyRegistryRoot as u32;
const WINDOW_ELAPSED: u32 = CustomRingError::WindowElapsed as u32;
const PROOF_FAILED: u32 = CustomRingError::ProofVerificationFailed as u32;

/// Every indexer call fails as unsupported.
struct NoIndexer;

#[async_trait]
impl AsyncRpc for NoIndexer {}

no_witnesses!(NoIndexer);

fn transfer(sender: &ShieldedKeypair) -> RingOperation<'_> {
    let mut transaction = ConfidentialTransaction::new(
        vec![note(sender, 10, 0, Some(ring().program_id()))],
        sender.pubkey(),
    )
    .unwrap();
    transaction
        .transfer_sol(&sender.shielded_address().unwrap(), 4)
        .unwrap();
    CustomRingTransfer::new(CustomRingTransferInput {
        ring: ring(),
        sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction,
    })
    .into()
}

/// A submission whose signed attempt is already out, valid through block height 20.
fn pending<'a>(
    operation: RingOperation<'a>,
    sender: &ShieldedKeypair,
    attempts: u8,
) -> RingSubmission<'a> {
    let message = compile_message(
        &sender.pubkey(),
        &[],
        Default::default(),
        ComputeBudgetConfig::new(1_400_000),
    )
    .unwrap();
    let mut submission = RingSubmission::new(operation);
    submission.pending = Some(Attempt {
        transaction: sign_transaction(message, &[sender]).unwrap(),
        last_valid_block_height: 20,
    });
    submission.attempts = attempts;
    submission
}

fn client(rpc: RpcClient) -> AsyncZolanaClient<AsyncSolanaRpc, NoIndexer> {
    AsyncZolanaClient::new(
        AsyncSolanaRpc::with_client(rpc),
        NoIndexer,
        AsyncProverClient::local(),
    )
}

fn mocked(
    status: Value,
    block_height: u64,
    slot: u64,
) -> AsyncZolanaClient<AsyncSolanaRpc, NoIndexer> {
    client(RpcClient::new_mock_with_mocks(
        "succeeds".into(),
        [
            (
                RpcRequest::GetSignatureStatuses,
                json!({"context": {"slot": 9}, "value": [status]}),
            ),
            (RpcRequest::GetBlockHeight, json!(block_height)),
            (RpcRequest::GetSlot, json!(slot)),
        ]
        .into_iter()
        .collect(),
    ))
}

fn confirmed(slot: u64) -> Value {
    json!({"slot": slot, "confirmations": 1, "confirmationStatus": "confirmed", "err": null, "status": {"Ok": null}})
}

fn failed(index: u8, code: u32) -> Value {
    let error = json!({"InstructionError": [index, {"Custom": code}]});
    json!({"slot": 9, "confirmations": 1, "confirmationStatus": "confirmed", "err": error, "status": {"Err": error}})
}

async fn send<R: AsyncRpc, I: AsyncIndexer>(
    submission: &mut RingSubmission<'_>,
    client: &AsyncZolanaClient<R, I>,
    payer: &ShieldedKeypair,
) -> Result<SubmissionStatus, RingError> {
    fn requires_send<T: Send>(value: T) -> T {
        value
    }
    Box::pin(requires_send(submission.send(client, payer, &[]))).await
}

/// Enforces the lookup, expiry, then fresh lookup order for one pending signature.
struct ExpiryObservation {
    requests: Arc<AtomicUsize>,
    statuses_after_expiry: Option<Value>,
}

#[async_trait]
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

fn expiry(
    requests: &Arc<AtomicUsize>,
    statuses_after_expiry: Option<Value>,
) -> AsyncZolanaClient<AsyncSolanaRpc, NoIndexer> {
    client(RpcClient::new_sender(
        ExpiryObservation {
            requests: requests.clone(),
            statuses_after_expiry,
        },
        Default::default(),
    ))
}

#[tokio::test]
async fn unknown_outcome_only_polls_the_original_signature() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let mut submission = pending(transfer(&sender), &sender, 1);
    let transaction = submission.pending_transaction().unwrap().clone();
    for _ in 0..2 {
        assert_eq!(
            send(&mut submission, &mocked(Value::Null, 10, 0), &sender)
                .await
                .unwrap(),
            SubmissionStatus::Pending {
                signature: transaction.signatures[0]
            }
        );
        assert_eq!(submission.attempts(), 1);
        assert_eq!(submission.pending_transaction(), Some(&transaction));
    }
}

/// Rejects status lookups and counts whether an unsafe expiry check follows.
struct StatusFailure {
    status_calls: Arc<AtomicUsize>,
    height_calls: Arc<AtomicUsize>,
    block_height: u64,
}

#[async_trait]
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

#[tokio::test]
async fn a_status_transport_failure_preserves_the_pending_attempt_past_expiry() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    for attempts in [1, MAX_ATTEMPTS] {
        for block_height in [10, 21] {
            let mut submission = pending(transfer(&sender), &sender, attempts);
            let transaction = submission.pending_transaction().unwrap().clone();
            let status_calls = Arc::new(AtomicUsize::new(0));
            let height_calls = Arc::new(AtomicUsize::new(0));
            let failing = client(RpcClient::new_sender(
                StatusFailure {
                    status_calls: status_calls.clone(),
                    height_calls: height_calls.clone(),
                    block_height,
                },
                Default::default(),
            ));
            for _ in 0..2 {
                assert_eq!(
                    send(&mut submission, &failing, &sender).await.unwrap(),
                    SubmissionStatus::Pending {
                        signature: transaction.signatures[0]
                    }
                );
                assert_eq!(submission.attempts(), attempts);
                assert_eq!(submission.pending_transaction(), Some(&transaction));
            }
            assert_eq!(status_calls.load(Ordering::Relaxed), 2);
            assert_eq!(height_calls.load(Ordering::Relaxed), 0);
            assert_eq!(
                send(
                    &mut submission,
                    &mocked(confirmed(9), block_height, 0),
                    &sender
                )
                .await
                .unwrap(),
                SubmissionStatus::Confirmed {
                    signature: transaction.signatures[0],
                    slot: 9,
                }
            );
        }
    }
}

#[tokio::test]
async fn malformed_status_counts_preserve_the_pending_attempt_past_expiry() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    for statuses in [json!([]), json!([null, null]), json!([confirmed(9), null])] {
        let mut submission = pending(transfer(&sender), &sender, MAX_ATTEMPTS);
        let transaction = submission.pending_transaction().unwrap().clone();
        let rpc = client(RpcClient::new_mock_with_mocks(
            "succeeds".into(),
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
            send(&mut submission, &rpc, &sender).await.unwrap(),
            SubmissionStatus::Pending {
                signature: transaction.signatures[0],
            }
        );
        assert_eq!(submission.attempts(), MAX_ATTEMPTS);
        assert_eq!(submission.pending_transaction(), Some(&transaction));
    }
}

#[tokio::test]
async fn an_expired_blockhash_fails_the_last_attempt() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let mut submission = pending(transfer(&sender), &sender, MAX_ATTEMPTS);
    let signature = submission.pending_transaction().unwrap().signatures[0];
    let requests = Arc::new(AtomicUsize::new(0));
    assert_eq!(
        send(
            &mut submission,
            &expiry(&requests, Some(json!([null]))),
            &sender
        )
        .await
        .unwrap(),
        SubmissionStatus::Failed {
            signature,
            error: TransactionError::BlockhashNotFound
        }
    );
    assert_eq!(requests.load(Ordering::Relaxed), 3);
    assert!(submission.pending_transaction().is_none());
}

#[tokio::test]
async fn a_transaction_landing_during_the_expiry_check_confirms_the_original_signature() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let mut submission = pending(transfer(&sender), &sender, 1);
    let signature = submission.pending_transaction().unwrap().signatures[0];
    let requests = Arc::new(AtomicUsize::new(0));
    let rpc = expiry(&requests, Some(json!([confirmed(20)])));
    for _ in 0..2 {
        assert_eq!(
            send(&mut submission, &rpc, &sender).await.unwrap(),
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

#[tokio::test]
async fn a_failed_transaction_landing_during_the_expiry_check_keeps_its_actual_error() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let mut submission = pending(transfer(&sender), &sender, 1);
    let signature = submission.pending_transaction().unwrap().signatures[0];
    let requests = Arc::new(AtomicUsize::new(0));
    assert_eq!(
        send(
            &mut submission,
            &expiry(&requests, Some(json!([failed(1, 8145)]))),
            &sender
        )
        .await
        .unwrap(),
        SubmissionStatus::Failed {
            signature,
            error: TransactionError::InstructionError(1, InstructionError::Custom(8145)),
        }
    );
    assert_eq!(requests.load(Ordering::Relaxed), 3);
    assert_eq!(submission.attempts(), 1);
    assert!(submission.pending_transaction().is_none());
}

#[tokio::test]
async fn an_unresolved_post_expiry_lookup_preserves_the_original_attempt_until_confirmation() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    for statuses_after_expiry in [
        None,
        Some(json!([])),
        Some(json!([null, null])),
        Some(json!([confirmed(20), null])),
        Some(json!([
            {"slot": 20, "confirmations": 0, "confirmationStatus": "processed", "err": null, "status": {"Ok": null}}
        ])),
    ] {
        for attempts in [1, MAX_ATTEMPTS] {
            let mut submission = pending(transfer(&sender), &sender, attempts);
            let transaction = submission.pending_transaction().unwrap().clone();
            let signature = transaction.signatures[0];
            let requests = Arc::new(AtomicUsize::new(0));
            let uncertain = expiry(&requests, statuses_after_expiry.clone());
            assert_eq!(
                send(&mut submission, &uncertain, &sender).await.unwrap(),
                SubmissionStatus::Pending { signature }
            );
            assert_eq!(requests.load(Ordering::Relaxed), 3);
            assert_eq!(submission.attempts(), attempts);
            assert_eq!(submission.pending_transaction(), Some(&transaction));
            assert_eq!(
                send(&mut submission, &mocked(confirmed(20), 21, 0), &sender)
                    .await
                    .unwrap(),
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

#[tokio::test]
async fn confirmation_finishes_once_and_releases_the_pending_attempt() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let mut submission = pending(transfer(&sender), &sender, 1);
    let signature = submission.pending_transaction().unwrap().signatures[0];
    let rpc = mocked(confirmed(9), 10, 0);
    for _ in 0..2 {
        assert_eq!(
            send(&mut submission, &rpc, &sender).await.unwrap(),
            SubmissionStatus::Confirmed { signature, slot: 9 }
        );
        assert_eq!(submission.attempts(), 1);
        assert!(submission.pending_transaction().is_none());
    }
}

#[tokio::test]
async fn unrelated_errors_and_the_third_failed_attempt_never_reprove() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    for (attempts, index, code) in [
        (1, 1, STALE_ROOT),
        (1, 0, 8145),
        (MAX_ATTEMPTS, 0, STALE_ROOT),
    ] {
        let mut submission = pending(transfer(&sender), &sender, attempts);
        let signature = submission.pending_transaction().unwrap().signatures[0];
        assert_eq!(
            send(
                &mut submission,
                &mocked(failed(index, code), 10, 0),
                &sender
            )
            .await
            .unwrap(),
            SubmissionStatus::Failed {
                signature,
                error: TransactionError::InstructionError(index, InstructionError::Custom(code))
            }
        );
        assert_eq!(submission.attempts(), attempts);
        assert!(submission.pending_transaction().is_none());
    }
}

/// A built instruction no tag names, a re-proof fails on it before any send.
fn untagged() -> RingOperation<'static> {
    Instruction {
        program_id: ring().program_id(),
        accounts: Vec::new(),
        data: vec![u8::MAX],
    }
    .into()
}

#[tokio::test]
async fn a_stale_root_or_an_elapsed_window_reproves_below_the_attempt_limit() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    for code in [STALE_ROOT, WINDOW_ELAPSED] {
        let mut submission = pending(untagged(), &sender, 1);
        assert!(matches!(
            send(&mut submission, &mocked(failed(0, code), 10, 0), &sender).await,
            Err(RingError::Program(CustomRingError::InvalidInstructionData))
        ));
        assert_eq!(submission.attempts(), 1);
        assert!(submission.pending_transaction().is_none());
    }
}

/// A failed proof is final whatever the slot, the window has its own code.
#[tokio::test]
async fn a_failed_proof_never_reproves() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let mut submission = pending(untagged(), &sender, 1);
    let signature = submission.pending_transaction().unwrap().signatures[0];
    assert_eq!(
        send(
            &mut submission,
            &mocked(failed(0, PROOF_FAILED), 10, 600),
            &sender
        )
        .await
        .unwrap(),
        SubmissionStatus::Failed {
            signature,
            error: TransactionError::InstructionError(0, InstructionError::Custom(PROOF_FAILED))
        }
    );
}

#[test]
fn only_the_bound_ring_failure_can_retry() {
    let error =
        |index, code| TransactionError::InstructionError(index, InstructionError::Custom(code));
    assert!(retryable(&error(0, STALE_ROOT)));
    assert!(!retryable(&error(1, STALE_ROOT)));
    assert!(retryable(&error(0, WINDOW_ELAPSED)));
    assert!(!retryable(&error(1, WINDOW_ELAPSED)));
    assert!(!retryable(&error(0, PROOF_FAILED)));
    assert!(!retryable(&error(
        0,
        CustomRingError::InvalidWindowIndex as u32
    )));
    assert!(!retryable(&error(0, 8145)));
    assert!(!retryable(&TransactionError::AccountInUse));
    assert!(retryable(&TransactionError::BlockhashNotFound));
}

#[test]
fn retry_decisions_preserve_unknown_attempts_and_stop_at_the_limit() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    for code in [STALE_ROOT, WINDOW_ELAPSED] {
        let mut submission = pending(transfer(&sender), &sender, 1);
        let transaction = submission.pending_transaction().unwrap().clone();
        let signature = transaction.signatures[0];
        assert_eq!(
            submission.settle(signature, Outcome::Unknown),
            Some(SubmissionStatus::Pending { signature })
        );
        assert_eq!(submission.pending_transaction(), Some(&transaction));
        let failure = || {
            Outcome::Failed(TransactionError::InstructionError(
                0,
                InstructionError::Custom(code),
            ))
        };
        assert!(submission.settle(signature, failure()).is_none());
        assert!(submission.pending_transaction().is_none());
        submission.attempts = MAX_ATTEMPTS;
        assert!(matches!(
            submission.settle(signature, failure()),
            Some(SubmissionStatus::Failed { .. })
        ));
    }
}

#[test]
fn only_a_confirmed_status_settles_a_signature() {
    let status = |confirmation: &str, err: Value| {
        serde_json::from_value::<TransactionStatus>(json!({
            "slot": 7,
            "confirmations": 1,
            "confirmationStatus": confirmation,
            "err": err,
            "status": {"Ok": null},
        }))
        .unwrap()
    };
    assert_eq!(decode_status(vec![None]), None);
    assert_eq!(decode_status(Vec::new()), Some(Outcome::Unknown));
    assert_eq!(decode_status(vec![None, None]), Some(Outcome::Unknown));
    assert_eq!(
        decode_status(vec![Some(status("processed", Value::Null))]),
        Some(Outcome::Unknown)
    );
    for confirmation in ["confirmed", "finalized"] {
        assert_eq!(
            decode_status(vec![Some(status(confirmation, Value::Null))]),
            Some(Outcome::Confirmed { slot: 7 })
        );
    }
    assert_eq!(
        decode_status(vec![Some(status(
            "confirmed",
            json!({"InstructionError": [0, {"Custom": 3}]})
        ))]),
        Some(Outcome::Failed(TransactionError::InstructionError(
            0,
            InstructionError::Custom(3)
        )))
    );
}

#[tokio::test]
async fn a_built_instruction_takes_the_budget_its_tag_names() {
    let payer = ShieldedKeypair::new_ed25519().unwrap().pubkey();
    let client = mocked(Value::Null, 10, 0);
    let instruction = Instruction {
        program_id: ring().program_id(),
        accounts: Vec::new(),
        data: vec![crate::tag::SET_PAUSED, 1],
    };
    let proved = RingOperation::Instruction(instruction.clone())
        .prove(&client, payer)
        .await
        .unwrap();
    assert_eq!(proved.instruction, instruction);
    assert_eq!(
        proved.budget,
        ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::SetPaused))
    );
    assert!(matches!(
        RingOperation::Instruction(Instruction {
            data: Vec::new(),
            ..instruction
        })
        .prove(&client, payer)
        .await,
        Err(RingError::Program(CustomRingError::InvalidInstructionData))
    ));
}

fn operations(sender: &ShieldedKeypair) -> Vec<RingOperation<'_>> {
    let program = ring().program_id();
    let wallets = vec![
        note(sender, 3, 0, Some(program)),
        note(sender, 5, 0, Some(program)),
    ];
    let inputs = wallets.iter().map(Into::into).collect();
    let merge = CustomRingMerge::new(ring(), wallets, None)
        .unwrap()
        .encrypt(sender)
        .unwrap();
    vec![
        transfer(sender),
        DelegateTransfer::new(DelegateTransferInput {
            ring: ring(),
            delegate: sender.pubkey(),
            payer: sender.pubkey(),
            source_nullifier_key: &sender.nullifier_key,
            inputs,
            outputs: vec![DelegateOutput {
                recipient: sender.shielded_address().unwrap(),
                asset: SOL_MINT,
                amount: 8,
            }],
        })
        .into(),
        RegisterSpend {
            ring: ring(),
            payer: sender.pubkey(),
        }
        .into(),
        RegisterKey {
            ring: ring(),
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
        untagged(),
    ]
}

#[tokio::test]
async fn every_operation_keeps_the_signed_attempt_until_confirmation() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    for operation in operations(&sender) {
        let mut submission = pending(operation, &sender, 1);
        let transaction = submission.pending_transaction().unwrap().clone();
        let signature = transaction.signatures[0];
        assert_eq!(
            send(&mut submission, &mocked(Value::Null, 10, 0), &sender)
                .await
                .unwrap(),
            SubmissionStatus::Pending { signature }
        );
        assert_eq!(submission.pending_transaction(), Some(&transaction));
        assert_eq!(submission.attempts(), 1);
    }
}

/// Serves a windowed policy and a slot sequence, the last slot repeats.
struct WindowRpc {
    ring: CustomRing,
    policy: Account,
    slots: Mutex<VecDeque<u64>>,
    slot_reads: AtomicUsize,
    policy_reads: AtomicUsize,
}

#[async_trait]
impl AsyncRpc for WindowRpc {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        assert_eq!(address, self.ring.policy_config_pda());
        self.policy_reads.fetch_add(1, Ordering::Relaxed);
        Ok(Some(self.policy.clone()))
    }

    async fn get_slot(&self) -> Result<u64, ClientError> {
        self.slot_reads.fetch_add(1, Ordering::Relaxed);
        let mut slots = self.slots.lock().unwrap();
        Ok(match slots.len() {
            1 => slots[0],
            _ => slots.pop_front().unwrap(),
        })
    }
}

#[tokio::test]
async fn a_closing_window_is_waited_out_and_proved_again_without_an_attempt() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let asset = *Member::asset(&SOL_MINT).unwrap().as_bytes();
    let table = RuleTable::builder()
        .windowed(NonZeroU64::new(1000).unwrap())
        .velocity(&[VelocityRow {
            asset,
            cap: 100,
            cosign_above: 0,
        }])
        .build();
    let config = pinned(ring(), &table, ring().namespace_pda(), PoolTree::from_id(0));
    let rpc = WindowRpc {
        ring: ring(),
        policy: account(ring().program_id(), &config),
        // 1950 lies in the guard of window 1, its successor starts at 2000.
        slots: Mutex::new(VecDeque::from([1950, 1990, 2000])),
        slot_reads: AtomicUsize::new(0),
        policy_reads: AtomicUsize::new(0),
    };
    let client = AsyncZolanaClient::new(rpc, NoIndexer, AsyncProverClient::local());
    let mut submission = RingSubmission::new(RegisterSpend {
        ring: ring(),
        payer: sender.pubkey(),
    });
    // The second proof reaches the indexer, which refuses every call.
    assert!(matches!(
        send(&mut submission, &client, &sender).await,
        Err(RingError::Client(ClientError::UnsupportedRpcMethod(
            "get_non_inclusion_proofs"
        )))
    ));
    assert_eq!(submission.attempts(), 0);
    assert!(submission.pending_transaction().is_none());
    let rpc = client.rpc();
    assert_eq!(rpc.policy_reads.load(Ordering::Relaxed), 2);
    // One read refuses, two wait for the boundary, one proves again.
    assert_eq!(rpc.slot_reads.load(Ordering::Relaxed), 4);
}
