use std::sync::Mutex;

use async_trait::async_trait;
use solana_epoch_info::EpochInfo;
use solana_transaction::TransactionError as ChainError;
use solana_transaction_status_client_types::TransactionStatus;

use super::*;
use crate::rpc::{
    Context, GetShieldedTransactionsBySignatureResponse, IndexedShieldedTransaction,
    ShieldedTransaction,
};

/// A Solana RPC and its indexer: the ledger holds `status`, the block
/// height stays `height` and the slot 100; the indexer, at
/// `indexer_slot`, has the transaction when `indexed`. Counts the status
/// lookups.
struct Chain {
    status: Option<TransactionStatus>,
    height: u64,
    indexed: bool,
    indexer_slot: u64,
    lookups: Mutex<u32>,
}

impl Chain {
    fn new(status: Option<TransactionStatus>, height: u64) -> Self {
        Self {
            status,
            height,
            indexed: false,
            indexer_slot: 100,
            lookups: Mutex::new(0),
        }
    }
}

fn landed(err: Option<ChainError>) -> Option<TransactionStatus> {
    Some(TransactionStatus {
        slot: 1,
        confirmations: Some(1),
        status: Ok(()),
        err,
        confirmation_status: Some(TransactionConfirmationStatus::Confirmed),
    })
}

fn epoch_info(block_height: u64, absolute_slot: u64) -> EpochInfo {
    EpochInfo {
        epoch: 0,
        slot_index: absolute_slot,
        slots_in_epoch: 432_000,
        absolute_slot,
        block_height,
        transaction_count: None,
    }
}

#[async_trait]
impl AsyncRpc for Chain {
    async fn get_epoch_info(&self) -> Result<EpochInfo, ClientError> {
        Ok(epoch_info(self.height, 100))
    }

    async fn get_signature_statuses_with_history(
        &self,
        _: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        *self.lookups.lock().unwrap() += 1;
        Ok(vec![self.status.clone()])
    }

    async fn get_shielded_transactions_by_signature(
        &self,
        signature: Signature,
        _: Option<crate::rpc::IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
        let found = IndexedShieldedTransaction {
            event_index: 0,
            transaction: ShieldedTransaction {
                slot: 1,
                tx_signature: signature,
                event_index: Some(0),
                tx_viewing_pk: None,
                salt: None,
                output_slots: Vec::new(),
                messages: Vec::new(),
                nullifiers: Vec::new(),
                proofless: false,
                ring_config: None,
                ring_program_id: None,
            },
        };
        Ok(GetShieldedTransactionsBySignatureResponse {
            context: Context {
                block_time: 0,
                slot: self.indexer_slot,
            },
            output_tree_id: None,
            transactions: self.indexed.then_some(found).into_iter().collect(),
        })
    }
}

const QUICK: IndexerPollConfig = IndexerPollConfig {
    num_retries: 2,
    delay_ms: 1,
    max_delay_ms: 1,
};

async fn settled(chain: &Chain, height: Option<u64>) -> Result<(), ClientError> {
    settle(
        chain,
        chain,
        Signature::from([3; 64]),
        height,
        QUICK,
        Duration::from_secs(60),
    )
    .await
}

/// The status cache holds recent transactions only: the indexer finds one
/// that landed long ago, with or without its last valid block height.
#[tokio::test(start_paused = true)]
async fn the_indexer_finds_a_transaction_the_cache_dropped() {
    let old = Chain {
        indexed: true,
        ..Chain::new(None, 1_000)
    };
    assert!(settled(&old, Some(100)).await.is_ok());
    assert!(settled(&old, None).await.is_ok());
}

#[tokio::test(start_paused = true)]
async fn a_failure_solana_confirmed_is_the_chains_error() {
    let refused = Chain::new(landed(Some(ChainError::InsufficientFundsForFee)), 99);
    assert!(matches!(
        settled(&refused, Some(100)).await,
        Err(ClientError::SolanaRpcTransaction { source, .. })
            if source.get_transaction_error() == Some(ChainError::InsufficientFundsForFee)
    ));
}

/// Expired only once the blockhash expired and the indexer reached the
/// slot where it did; an indexer behind that slot cannot tell.
#[tokio::test(start_paused = true)]
async fn expired_only_once_the_indexer_passed_the_expiry() {
    let expired = Chain::new(None, 101);
    assert!(matches!(
        settled(&expired, Some(100)).await,
        Err(ClientError::TransactionExpired { .. })
    ));
    assert_eq!(*expired.lookups.lock().unwrap(), 1);

    let behind = Chain {
        indexer_slot: 99,
        ..Chain::new(None, 101)
    };
    assert!(matches!(
        settled(&behind, Some(100)).await,
        Err(ClientError::TransactionOutcomeUnknown { .. })
    ));
    assert_eq!(*behind.lookups.lock().unwrap(), QUICK.num_retries + 1);
}

/// A transaction Solana confirmed that the indexer never records, such as
/// a pool call without a private event, ends neither done nor expired.
#[tokio::test(start_paused = true)]
async fn confirmed_without_an_event_is_not_indexed() {
    let confirmed = Chain::new(landed(None), 1_000);
    assert!(matches!(
        settled(&confirmed, Some(100)).await,
        Err(ClientError::TransactionNotIndexed { .. })
    ));
}

/// A block height that never passes the last valid one cannot hold the
/// wait past its schedule.
#[tokio::test(start_paused = true)]
async fn a_frozen_block_height_ends_unknown_on_schedule() {
    let frozen = Chain::new(None, 99);
    assert!(matches!(
        settled(&frozen, Some(100)).await,
        Err(ClientError::TransactionOutcomeUnknown { .. })
    ));
    assert_eq!(*frozen.lookups.lock().unwrap(), QUICK.num_retries + 1);
}

#[tokio::test(start_paused = true)]
async fn missing_confirmation_status_is_not_a_confirmed_failure() {
    let mut status = landed(Some(ChainError::InsufficientFundsForFee)).unwrap();
    status.confirmation_status = None;
    status.confirmations = Some(0);
    let chain = Chain::new(Some(status), 99);
    let outcome = settled(&chain, Some(100)).await;
    assert!(
        matches!(outcome, Err(ClientError::TransactionOutcomeUnknown { .. })),
        "unconfirmed failure must remain unknown, got {outcome:?}"
    );
}

struct NeverAnswers;

#[async_trait]
impl AsyncRpc for NeverAnswers {
    async fn get_shielded_transactions_by_signature(
        &self,
        _: Signature,
        _: Option<crate::rpc::IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
        std::future::pending().await
    }
}

#[tokio::test(start_paused = true)]
async fn deadline_bounds_a_hung_indexer_request() {
    let chain = Chain::new(landed(None), 99);
    let outcome = tokio::time::timeout(
        Duration::from_millis(50),
        settle(
            &chain,
            &NeverAnswers,
            Signature::from([3; 64]),
            Some(100),
            QUICK,
            Duration::from_millis(10),
        ),
    )
    .await;
    assert!(
        matches!(outcome, Ok(Err(ClientError::TransactionNotIndexed { .. }))),
        "the 10 ms deadline must bound a hung request: {outcome:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_confirmed_failure_cancels_a_pending_indexer() {
    use std::sync::atomic::{AtomicBool, Ordering};

    struct FailingChain(Chain);
    #[async_trait]
    impl AsyncRpc for FailingChain {
        async fn get_signature_statuses_with_history(
            &self,
            signatures: Vec<Signature>,
        ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
            tokio::task::yield_now().await;
            self.0.get_signature_statuses_with_history(signatures).await
        }
    }

    struct PendingIndexer(AtomicBool);
    struct Cancelled<'a>(&'a AtomicBool);
    impl Drop for Cancelled<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    #[async_trait]
    impl AsyncRpc for PendingIndexer {
        async fn get_shielded_transactions_by_signature(
            &self,
            _: Signature,
            _: Option<crate::rpc::IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
            let _cancelled = Cancelled(&self.0);
            std::future::pending().await
        }
    }

    let chain = FailingChain(Chain::new(
        landed(Some(ChainError::InsufficientFundsForFee)),
        99,
    ));
    let indexer = PendingIndexer(AtomicBool::new(false));
    let start = tokio::time::Instant::now();
    let result = settle(
        &chain,
        &indexer,
        Signature::from([3; 64]),
        Some(100),
        QUICK,
        Duration::from_secs(60),
    )
    .await;
    assert!(matches!(
        result,
        Err(ClientError::SolanaRpcTransaction { source, .. })
            if source.get_transaction_error() == Some(ChainError::InsufficientFundsForFee)
    ));
    assert_eq!(start.elapsed(), Duration::ZERO);
    assert_eq!(*chain.0.lookups.lock().unwrap(), 1);
    assert!(indexer.0.load(Ordering::SeqCst));
}
impl crate::prover::witness::AsyncWitnessReader for Chain {
    async fn input_witnesses(
        &self,
        _: &[&zolana_transaction::utxo::SppProofInputUtxo],
        _: &[[u8; 32]],
        _: Option<crate::rpc::IndexerRpcConfig>,
    ) -> Result<crate::prover::witness::InputWitnesses, ClientError> {
        Err(ClientError::UnsupportedRpcMethod("input_witnesses"))
    }
}

fn unused_prover() -> crate::prover::AsyncProverClient {
    #[derive(Debug)]
    struct NoHttp;
    impl zolana_api::HttpClient for NoHttp {
        fn send<'a>(&'a self, _: zolana_api::HttpRequest) -> zolana_api::HttpFuture<'a> {
            panic!("confirmation must not call the prover")
        }
    }
    crate::prover::AsyncProverClient::with_client("http://unused.invalid".into(), NoHttp)
}

#[tokio::test(start_paused = true)]
async fn post_broadcast_failures_retain_the_signature_and_original_error() {
    struct Broadcast {
        sent: Mutex<u32>,
        chain: Chain,
    }
    #[async_trait]
    impl AsyncRpc for Broadcast {
        async fn send_transaction_with_config(
            &self,
            transaction: &VersionedTransaction,
            _: RpcSendTransactionConfig,
        ) -> Result<Signature, ClientError> {
            *self.sent.lock().unwrap() += 1;
            Ok(transaction.signatures[0])
        }
        async fn get_signature_statuses_with_history(
            &self,
            signatures: Vec<Signature>,
        ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
            self.chain
                .get_signature_statuses_with_history(signatures)
                .await
        }
        async fn get_epoch_info(&self) -> Result<EpochInfo, ClientError> {
            self.chain.get_epoch_info().await
        }
    }
    struct BrokenIndexer(fn() -> ClientError);
    #[async_trait]
    impl AsyncRpc for BrokenIndexer {
        async fn get_shielded_transactions_by_signature(
            &self,
            _: Signature,
            _: Option<crate::rpc::IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
            Err((self.0)())
        }
    }
    impl crate::prover::witness::AsyncWitnessReader for BrokenIndexer {
        async fn input_witnesses(
            &self,
            _: &[&zolana_transaction::utxo::SppProofInputUtxo],
            _: &[[u8; 32]],
            _: Option<crate::rpc::IndexerRpcConfig>,
        ) -> Result<crate::prover::witness::InputWitnesses, ClientError> {
            panic!("recovery must not request witnesses")
        }
    }
    let signature = Signature::from([3; 64]);
    let failures: [fn() -> ClientError; 3] = [
        || ClientError::UnsupportedRpcMethod("get_shielded_transactions_by_signature"),
        || ClientError::Indexer("malformed indexer response".into()),
        || ClientError::Indexer("wrong transaction's event".into()),
    ];
    for failure in failures {
        for chain_failed in [false, true] {
            let client = AsyncZolanaClient::new(
                Broadcast {
                    sent: Mutex::new(0),
                    chain: Chain::new(
                        landed(chain_failed.then_some(ChainError::InsufficientFundsForFee)),
                        99,
                    ),
                },
                BrokenIndexer(failure),
                unused_prover(),
            );
            let error = client
                .send_private_transaction(
                    VersionedTransaction {
                        signatures: vec![signature],
                        message: solana_message::VersionedMessage::Legacy(
                            solana_message::Message::default(),
                        ),
                    },
                    100,
                )
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains(&signature.to_string()),
                "lost signature: {error:?}"
            );
            assert!(
                matches!(&error, ClientError::PrivateTransactionRecoveryFailed { signature: saved, last_valid_block_height: 100, .. } if *saved == signature)
            );
            let ClientError::PrivateTransactionRecoveryFailed { source, .. } = &error else {
                panic!("missing recovery coordinates: {error:?}");
            };
            assert_eq!(
                std::error::Error::source(&error)
                    .expect("error source")
                    .to_string(),
                source.to_string()
            );
            let source = source.as_ref();
            if chain_failed {
                assert!(
                    matches!(source, ClientError::SolanaRpcTransaction { source, .. } if source.get_transaction_error() == Some(ChainError::InsufficientFundsForFee))
                );
            } else {
                assert_eq!(source.to_string(), failure().to_string());
            }
            assert_eq!(*client.rpc.sent.lock().unwrap(), 1);
        }
    }
}

/// An RPC whose send fails with `failure`, over a chain where the
/// transaction landed and was indexed.
struct LostResponse {
    failure: fn() -> ClientError,
    chain: Chain,
}

#[async_trait]
impl AsyncRpc for LostResponse {
    async fn send_transaction_with_config(
        &self,
        _: &VersionedTransaction,
        _: solana_rpc_client_api::config::RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        Err((self.failure)())
    }

    async fn process_transaction(&self, _: VersionedTransaction) -> Result<Signature, ClientError> {
        Err((self.failure)())
    }

    async fn get_signature_statuses_with_history(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        self.chain
            .get_signature_statuses_with_history(signatures)
            .await
    }
}

async fn send_through(failure: fn() -> ClientError) -> (Result<Signature, ClientError>, u32) {
    let indexed = Chain {
        indexed: true,
        ..Chain::new(None, 99)
    };
    let client = AsyncZolanaClient::new(
        LostResponse {
            failure,
            chain: Chain::new(landed(None), 99),
        },
        indexed,
        unused_prover(),
    );
    let transaction = VersionedTransaction {
        signatures: vec![Signature::from([3; 64])],
        message: solana_message::VersionedMessage::Legacy(solana_message::Message::default()),
    };
    let result = client.send_private_transaction(transaction, 100).await;
    let lookups = *client.rpc.chain.lookups.lock().unwrap();
    (result, lookups)
}

/// A send whose connection dropped may have broadcast the transaction, so
/// its signature decides the outcome.
#[tokio::test(start_paused = true)]
async fn a_send_that_lost_its_response_is_recovered_by_signature() {
    let (result, lookups) = send_through(|| ClientError::SolanaRpcTransaction {
        operation: "send_transaction_with_config",
        source: std::io::Error::from(std::io::ErrorKind::ConnectionReset).into(),
    })
    .await;
    assert_eq!(result.unwrap(), Signature::from([3; 64]));
    assert_eq!(lookups, 1);
}

/// An RPC that answered with an error refused the transaction; there is
/// nothing to wait for.
#[tokio::test(start_paused = true)]
async fn a_refused_send_is_returned_without_waiting() {
    let (result, lookups) = send_through(|| ClientError::SolanaRpcTransaction {
        operation: "send_transaction_with_config",
        source: RpcError::RpcResponseError {
            code: -32002,
            message: "Transaction simulation failed".into(),
            data: solana_rpc_client_api::request::RpcResponseErrorData::Empty,
        }
        .into(),
    })
    .await;
    assert!(
        matches!(
            result,
            Err(ClientError::SolanaRpcTransaction {
                operation: "send_transaction_with_config",
                ..
            })
        ),
        "{result:?}"
    );
    assert_eq!(lookups, 0);
}

/// Private sends must use the send-only method, then recover by signature;
/// an error from an adapter's combined confirmation poll is not a rejection.
#[tokio::test(start_paused = true)]
async fn a_private_send_does_not_use_the_adapters_confirmation_poll() {
    struct SendOnly {
        sent: Mutex<u32>,
        combined: Mutex<u32>,
    }
    #[async_trait]
    impl AsyncRpc for SendOnly {
        async fn send_transaction_with_config(
            &self,
            transaction: &VersionedTransaction,
            config: solana_rpc_client_api::config::RpcSendTransactionConfig,
        ) -> Result<Signature, ClientError> {
            assert_eq!(
                config.preflight_commitment,
                Some(CommitmentLevel::Confirmed)
            );
            assert!(!config.skip_preflight);
            *self.sent.lock().unwrap() += 1;
            Ok(transaction.signatures[0])
        }

        async fn process_transaction(
            &self,
            _: VersionedTransaction,
        ) -> Result<Signature, ClientError> {
            *self.combined.lock().unwrap() += 1;
            Err(ClientError::SolanaRpcTransaction {
                operation: "process_transaction",
                source: RpcError::RpcResponseError {
                    code: -32005,
                    message: "node unhealthy during confirmation".into(),
                    data: solana_rpc_client_api::request::RpcResponseErrorData::Empty,
                }
                .into(),
            })
        }
    }
    let client = AsyncZolanaClient::new(
        SendOnly {
            sent: Mutex::new(0),
            combined: Mutex::new(0),
        },
        Chain {
            indexed: true,
            ..Chain::new(None, 99)
        },
        unused_prover(),
    );
    let signature = Signature::from([3; 64]);
    let result = client
        .send_private_transaction(
            VersionedTransaction {
                signatures: vec![signature],
                message: solana_message::VersionedMessage::Legacy(
                    solana_message::Message::default(),
                ),
            },
            100,
        )
        .await;
    assert_eq!(result.unwrap(), signature);
    assert_eq!(*client.rpc.sent.lock().unwrap(), 1);
    assert_eq!(*client.rpc.combined.lock().unwrap(), 0);
}

#[test]
fn typescript_transaction_error_vectors_match_solana_serde() {
    let errors: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../../../test-vectors/solana_transaction_errors.json"
    ))
    .unwrap();
    for value in errors {
        let error: ChainError = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(error).unwrap(), value);
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryVector {
    name: String,
    last_valid_block_height: Option<u64>,
    rounds: Vec<RecoveryRound>,
    outcome: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryRound {
    status: String,
    failed: bool,
    height: u64,
    slot: u64,
    indexer_slot: u64,
    indexed: bool,
    indexer_error: bool,
}

/// Solana and the indexer are asked at once and the status no more once
/// it is confirmed, so each side counts its own rounds: the expiry read
/// follows the status read of its round.
struct ScriptedChain {
    rounds: Vec<RecoveryRound>,
    status_reads: Mutex<usize>,
    indexer_reads: Mutex<usize>,
}

impl ScriptedChain {
    fn status_round(&self) -> &RecoveryRound {
        &self.rounds[self.status_reads.lock().unwrap().saturating_sub(1)]
    }

    fn signature_status(&self) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        let round = self.status_round();
        match round.status.as_str() {
            "absent" => Ok(vec![None]),
            "rpcError" => Err(ClientError::Rpc("unavailable".into())),
            "invalid" => Ok(vec![]),
            _ => {
                let mut status =
                    landed(round.failed.then_some(ChainError::InsufficientFundsForFee)).unwrap();
                status.confirmation_status = match round.status.as_str() {
                    "processed" => Some(TransactionConfirmationStatus::Processed),
                    "confirmed" => Some(TransactionConfirmationStatus::Confirmed),
                    "finalized" => Some(TransactionConfirmationStatus::Finalized),
                    "missing" => None,
                    other => panic!("unknown vector status {other}"),
                };
                Ok(vec![Some(status)])
            }
        }
    }
}

#[async_trait]
impl AsyncRpc for ScriptedChain {
    fn should_retry(&self, _: &ClientError) -> bool {
        true
    }

    async fn get_signature_statuses_with_history(
        &self,
        _: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        *self.status_reads.lock().unwrap() += 1;
        self.signature_status()
    }

    async fn get_epoch_info(&self) -> Result<EpochInfo, ClientError> {
        let round = self.status_round();
        Ok(epoch_info(round.height, round.slot))
    }
    async fn get_shielded_transactions_by_signature(
        &self,
        signature: Signature,
        _: Option<crate::rpc::IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
        let round = {
            let mut reads = self.indexer_reads.lock().unwrap();
            *reads += 1;
            &self.rounds[*reads - 1]
        };
        if round.indexer_error {
            return Err(ClientError::Rpc("unavailable".into()));
        }
        let chain = Chain {
            indexed: round.indexed,
            indexer_slot: round.indexer_slot,
            ..Chain::new(None, round.height)
        };
        chain
            .get_shielded_transactions_by_signature(signature, None)
            .await
    }
}

#[tokio::test(start_paused = true)]
async fn matches_typescript_recovery_vectors() {
    let vectors: Vec<RecoveryVector> = serde_json::from_str(include_str!(
        "../../../../../test-vectors/private_transaction_confirmation.json"
    ))
    .unwrap();
    for vector in vectors {
        let attempts = vector.rounds.len();
        let chain = ScriptedChain {
            rounds: vector.rounds,
            status_reads: Mutex::new(0),
            indexer_reads: Mutex::new(0),
        };
        let result = settle(
            &chain,
            &chain,
            Signature::from([3; 64]),
            vector.last_valid_block_height,
            IndexerPollConfig::new(u32::try_from(attempts - 1).unwrap(), 0, 0),
            Duration::from_secs(60),
        )
        .await;
        let outcome = match result {
            Ok(()) => "indexed",
            Err(ClientError::TransactionExpired { .. }) => "expired",
            Err(ClientError::TransactionNotIndexed { .. }) => "notIndexed",
            Err(ClientError::TransactionOutcomeUnknown { .. }) => "unknown",
            Err(ClientError::SolanaRpcTransaction { .. }) => "failed",
            other => panic!("unexpected outcome {other:?}"),
        };
        assert_eq!(outcome, vector.outcome, "{}", vector.name);
        assert_eq!(
            *chain.indexer_reads.lock().unwrap(),
            attempts,
            "{}",
            vector.name
        );
    }
}

#[tokio::test(start_paused = true)]
async fn deadline_bounds_a_hung_rpc_without_claiming_expiry() {
    struct HungRpc;
    #[async_trait]
    impl AsyncRpc for HungRpc {
        async fn get_signature_statuses_with_history(
            &self,
            _: Vec<Signature>,
        ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
            std::future::pending().await
        }
    }
    let chain = Chain::new(None, 1_000);
    let start = tokio::time::Instant::now();
    assert!(matches!(
        settle(
            &HungRpc,
            &chain,
            Signature::from([3; 64]),
            Some(100),
            QUICK,
            Duration::from_millis(10)
        )
        .await,
        Err(ClientError::TransactionOutcomeUnknown { .. })
    ));
    assert_eq!(start.elapsed(), Duration::from_millis(10));
    assert_eq!(*chain.lookups.lock().unwrap(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_hung_rpc_does_not_erase_indexed_success() {
    struct HungRpc;
    #[async_trait]
    impl AsyncRpc for HungRpc {
        async fn get_signature_statuses_with_history(
            &self,
            _: Vec<Signature>,
        ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
            std::future::pending().await
        }
    }
    let indexed = Chain {
        indexed: true,
        ..Chain::new(None, 101)
    };
    let result = settle(
        &HungRpc,
        &indexed,
        Signature::from([3; 64]),
        Some(100),
        QUICK,
        Duration::from_millis(10),
    )
    .await;
    assert!(
        result.is_ok(),
        "the indexer already proved success: {result:?}"
    );
}
#[tokio::test(start_paused = true)]
async fn an_event_for_another_signature_cannot_confirm_this_transaction() {
    struct WrongSignature;
    #[async_trait]
    impl AsyncRpc for WrongSignature {
        async fn get_shielded_transactions_by_signature(
            &self,
            _: Signature,
            _: Option<crate::rpc::IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
            let chain = Chain {
                indexed: true,
                ..Chain::new(None, 100)
            };
            chain
                .get_shielded_transactions_by_signature(Signature::from([4; 64]), None)
                .await
        }
    }
    let chain = Chain::new(None, 101);
    let outcome = settle(
        &chain,
        &WrongSignature,
        Signature::from([3; 64]),
        Some(100),
        QUICK,
        Duration::from_secs(60),
    )
    .await;
    assert!(
        matches!(outcome, Err(ClientError::Indexer(_))),
        "an indexer that answers for another transaction cannot be waited out: {outcome:?}"
    );
    assert_eq!(*chain.lookups.lock().unwrap(), 1);
}

/// Waiting again cannot fix an indexer without the method, so the wait
/// ends with that error instead of an outcome that asks to wait again.
#[tokio::test(start_paused = true)]
async fn a_permanent_indexer_failure_is_returned_as_itself() {
    struct OldIndexer;
    #[async_trait]
    impl AsyncRpc for OldIndexer {}
    let chain = Chain::new(landed(None), 101);
    let result = settle(
        &chain,
        &OldIndexer,
        Signature::from([3; 64]),
        Some(100),
        QUICK,
        Duration::from_secs(60),
    )
    .await;
    assert!(
        matches!(
            result,
            Err(ClientError::UnsupportedRpcMethod(
                "get_shielded_transactions_by_signature"
            ))
        ),
        "{result:?}"
    );
    assert_eq!(*chain.lookups.lock().unwrap(), 1);
}

/// An RPC adapter without history-enabled statuses fails loudly, but only once
/// the indexer of the same round could not prove success.
#[tokio::test(start_paused = true)]
async fn an_rpc_without_the_status_lookup_is_returned_as_itself() {
    struct ConfirmOnly;
    #[async_trait]
    impl AsyncRpc for ConfirmOnly {
        async fn confirm_transaction(&self, _: Signature) -> Result<bool, ClientError> {
            Ok(true)
        }
    }
    let empty = Chain::new(None, 101);
    let result = settle(
        &ConfirmOnly,
        &empty,
        Signature::from([3; 64]),
        Some(100),
        QUICK,
        Duration::from_secs(60),
    )
    .await;
    assert!(
        matches!(
            result,
            Err(ClientError::UnsupportedRpcMethod(
                "get_signature_statuses_with_history"
            ))
        ),
        "{result:?}"
    );

    let indexed = Chain {
        indexed: true,
        ..Chain::new(None, 101)
    };
    assert!(settle(
        &ConfirmOnly,
        &indexed,
        Signature::from([3; 64]),
        Some(100),
        QUICK,
        Duration::from_secs(60),
    )
    .await
    .is_ok());
}

/// The last round's cause explains the outcome: an RPC that failed every
/// round is not reported as an indexer that lags.
#[tokio::test(start_paused = true)]
async fn an_rpc_outage_is_not_reported_as_indexer_lag() {
    struct Down;
    #[async_trait]
    impl AsyncRpc for Down {
        async fn get_signature_statuses_with_history(
            &self,
            _: Vec<Signature>,
        ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
            Err(ClientError::Rpc("connection refused".into()))
        }
    }
    let empty = Chain::new(None, 101);
    let result = settle(
        &Down,
        &empty,
        Signature::from([3; 64]),
        Some(100),
        QUICK,
        Duration::from_secs(60),
    )
    .await;
    assert!(
        matches!(
            &result,
            Err(ClientError::TransactionOutcomeUnknown { message, .. })
                if message == "Solana signature status lookup failed"
        ),
        "{result:?}"
    );
}

/// Once Solana confirmed the transaction, later rounds ask only the
/// indexer.
#[tokio::test(start_paused = true)]
async fn a_confirmed_status_is_not_asked_again() {
    let confirmed = Chain::new(landed(None), 99);
    assert!(matches!(
        settled(&confirmed, Some(100)).await,
        Err(ClientError::TransactionNotIndexed { .. })
    ));
    assert_eq!(*confirmed.lookups.lock().unwrap(), 1);
}
