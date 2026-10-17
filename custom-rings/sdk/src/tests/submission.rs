//! A child of `submission`, the pending attempt and its settlement are private to it.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
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
use zolana_transaction::{instructions::transact::ConfidentialTransaction, SOL_MINT};

use super::*;
use crate::{
    tests::support::{account, no_witnesses, note, ring},
    CustomRingMerge, CustomRingTransferInput, DelegateOutput, DelegateTransferInput,
};

const STALE_ROOT: u32 = CustomRingError::StaleMemberRegistryRoot as u32;
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
        bound: None,
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
async fn a_stale_root_reproves_below_the_attempt_limit() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let mut submission = pending(untagged(), &sender, 1);
    assert!(matches!(
        send(
            &mut submission,
            &mocked(failed(0, STALE_ROOT), 10, 0),
            &sender
        )
        .await,
        Err(RingError::Program(CustomRingError::InvalidInstructionData))
    ));
    assert_eq!(submission.attempts(), 1);
    assert!(submission.pending_transaction().is_none());
}

/// A failed proof is final whatever the slot.
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
    assert!(retryable(&error(0, STALE_ROOT), false));
    assert!(!retryable(&error(1, STALE_ROOT), false));
    assert!(!retryable(&error(0, PROOF_FAILED), false));
    assert!(retryable(&error(0, PROOF_FAILED), true));
    assert!(!retryable(&error(1, PROOF_FAILED), true));
    assert!(!retryable(&error(0, 8145), true));
    assert!(!retryable(&TransactionError::AccountInUse, true));
    assert!(retryable(&TransactionError::BlockhashNotFound, false));
}

#[test]
fn retry_decisions_preserve_unknown_attempts_and_stop_at_the_limit() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let mut submission = pending(transfer(&sender), &sender, 1);
    let transaction = submission.pending_transaction().unwrap().clone();
    let signature = transaction.signatures[0];
    assert_eq!(
        submission.settle(signature, Outcome::Unknown, false),
        Some(SubmissionStatus::Pending { signature })
    );
    assert_eq!(submission.pending_transaction(), Some(&transaction));
    let failure = || {
        Outcome::Failed(TransactionError::InstructionError(
            0,
            InstructionError::Custom(STALE_ROOT),
        ))
    };
    assert!(submission.settle(signature, failure(), false).is_none());
    assert!(submission.pending_transaction().is_none());
    submission.attempts = MAX_ATTEMPTS;
    assert!(matches!(
        submission.settle(signature, failure(), false),
        Some(SubmissionStatus::Failed { .. })
    ));
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

/// Serves one member registry root and one failed proof for every signature.
struct RegistryRpc {
    registry: Account,
}

#[async_trait]
impl AsyncRpc for RegistryRpc {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        assert_eq!(address, ring().member_registry_root_pda());
        Ok(Some(self.registry.clone()))
    }

    async fn get_signature_statuses_with_history(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        let status: TransactionStatus = serde_json::from_value(failed(0, PROOF_FAILED)).unwrap();
        Ok(signatures.iter().map(|_| Some(status.clone())).collect())
    }
}

/// The program reads the root at the named slot, a later root there fails the proof.
#[tokio::test]
async fn a_failed_proof_reproves_only_over_an_overwritten_registry_slot() {
    use custom_ring_interface::{MEMBER_REGISTRY_ROOT, MEMBER_REGISTRY_ROOT_HISTORY};
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let bound = BoundRoot::of(
        ring(),
        EscrowBinding::Registry(RegistryBinding {
            root_index: 3,
            root: [7; 32],
        }),
    );
    let bump = Address::find_program_address(&[MemberRegistryRoot::SEED], &ring().program_id()).1;
    for (held, retried) in [([8; 32], true), ([7; 32], false)] {
        let mut history = [[0; 32]; MEMBER_REGISTRY_ROOT_HISTORY];
        history[3] = held;
        let registry = MemberRegistryRoot {
            discriminator: MEMBER_REGISTRY_ROOT,
            next_index: 40u64.to_le_bytes(),
            bump,
            history_cursor: 3,
            history,
        };
        let client = AsyncZolanaClient::new(
            RegistryRpc {
                registry: account(ring().program_id(), &registry),
            },
            NoIndexer,
            AsyncProverClient::local(),
        );
        let mut submission = pending(untagged(), &sender, 1);
        submission.pending.as_mut().unwrap().bound = bound;
        let result = send(&mut submission, &client, &sender).await;
        if retried {
            // The re-proof reaches the untagged instruction and refuses it.
            assert!(matches!(
                result,
                Err(RingError::Program(CustomRingError::InvalidInstructionData))
            ));
        } else {
            assert!(matches!(result, Ok(SubmissionStatus::Failed { .. })));
        }
        assert_eq!(submission.attempts(), 1);
    }
}

#[test]
fn payload_and_address_limits_fail_before_submission() {
    let payer = Address::new_from_array([201; 32]);
    let mut instruction = Instruction {
        program_id: Address::new_from_array([202; 32]),
        accounts: Vec::new(),
        data: vec![0; 4096],
    };
    assert!(matches!(
        super::check_transaction_size(&payer, &instruction),
        Err(RingError::TransactionTooLarge { .. })
    ));
    let budget = ComputeBudgetConfig::new(1_400_000);
    let size = zolana_client::transaction_size(&payer, core::slice::from_ref(&instruction), budget)
        .unwrap();
    instruction
        .data
        .truncate(4096 - (size.bytes - instruction.data.len()));
    assert!(super::check_transaction_size(&payer, &instruction).is_ok());
    assert!(super::check_transaction_size_with_budget(
        &payer,
        &instruction,
        budget.with_priority_fee(1)
    )
    .is_err());
    instruction.data.clear();
    instruction.accounts = (1..=64)
        .map(|n| {
            solana_instruction::AccountMeta::new_readonly(Address::new_from_array([n; 32]), false)
        })
        .collect();
    assert!(super::check_transaction_size(&payer, &instruction).is_err());
    instruction.accounts.clear();
    assert!(super::check_transaction_size(&payer, &instruction).is_ok());
}

#[tokio::test]
async fn merge_sizes_are_checked_before_rpc_or_proving() {
    struct MissingRing(Arc<AtomicUsize>);

    #[async_trait]
    impl AsyncRpc for MissingRing {
        async fn get_account(&self, _address: Address) -> Result<Option<Account>, ClientError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }
    }

    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let payer = sender.pubkey();
    let input_tree = Address::new_from_array([212; 32]);
    for (count, cosigner, split_trees, fits) in [
        (50, false, false, true),
        (50, false, true, true),
        (50, true, false, false),
        (50, true, true, false),
        (49, true, false, true),
    ] {
        let inputs = (0..count)
            .map(|i| note(&sender, i + 1, 0, Some(ring().program_id())))
            .collect();
        let prepared = CustomRingMerge::new(ring(), inputs, None)
            .unwrap()
            .encrypt(&sender)
            .unwrap();
        let mut operation = RingMergeOperation::new(
            prepared,
            MergeProofInput {
                nullifier_key: sender.nullifier_key.clone(),
                input_tree,
                output_tree: if split_trees {
                    Address::new_from_array([213; 32])
                } else {
                    input_tree
                },
            },
        );
        if cosigner {
            operation = operation.with_cosigner(Address::new_from_array([211; 32]));
        }
        let requests = Arc::new(AtomicUsize::new(0));
        let client = AsyncZolanaClient::new(
            MissingRing(requests.clone()),
            NoIndexer,
            AsyncProverClient::local(),
        );
        let result = RingOperation::from(operation).prove(&client, payer).await;
        if fits {
            assert!(matches!(result, Err(RingError::MissingRingConfig)));
            assert_eq!(requests.load(Ordering::SeqCst), 1);
        } else {
            assert!(matches!(
                result,
                Err(RingError::TransactionTooLarge { bytes, limit }) if bytes > limit
            ));
            assert_eq!(requests.load(Ordering::SeqCst), 0);
        }
    }
}
