use std::time::Duration;

use solana_commitment_config::CommitmentConfig;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_transaction_status_client_types::TransactionConfirmationStatus;

use crate::{
    error::ClientError,
    rpc::{
        solana_rpc::{AsyncSolanaRpc, SolanaRpc},
        AsyncRpc, IndexerPollConfig,
    },
};

use super::{AsyncIndexer, AsyncZolanaClient, BlockingIndexer, ZolanaClient};

const WAIT_TIMEOUT: Duration = Duration::from_secs(60);

impl<I: AsyncIndexer> AsyncZolanaClient<AsyncSolanaRpc, I> {
    /// Recover a private transaction by signature without signing or sending.
    /// Uses Solana's history lookup and the indexer's private events.
    ///
    /// Save the signature and last valid block height before sending. Success
    /// means the private effects are indexed. A confirmed chain failure returns
    /// its Solana error. [`ClientError::TransactionExpired`] means the signature
    /// is absent, its blockhash expired, and the indexer processed through the
    /// slot where expiry was first observed without finding its event. Only
    /// that outcome permits rebuilding after an ambiguous send.
    ///
    /// [`ClientError::TransactionNotIndexed`] and
    /// [`ClientError::TransactionOutcomeUnknown`] keep the outcome unresolved;
    /// retain the checkpoint and wait again. The wait uses the client's poll
    /// schedule, bounded by 60 seconds including requests. Indexed evidence
    /// survives an RPC timeout; a confirmed chain failure takes precedence.
    ///
    /// Requires a complete private-event indexer on the same network as the
    /// RPC. Applies to deposits, transfers, withdrawals and merges, not arbitrary
    /// program calls or durable-nonce transactions. Omit the height if unknown;
    /// then the wait cannot establish expiry.
    pub async fn wait_for_private_transaction(
        &self,
        signature: Signature,
        last_valid_block_height: Option<u64>,
    ) -> Result<(), ClientError> {
        settle(
            self.rpc.client(),
            &self.indexer,
            signature,
            last_valid_block_height,
            self.indexer_config.poll,
            WAIT_TIMEOUT,
        )
        .await
    }
}

impl<I: BlockingIndexer> ZolanaClient<SolanaRpc, I> {
    /// See [`AsyncZolanaClient::wait_for_private_transaction`].
    pub fn wait_for_private_transaction_sync(
        &self,
        signature: Signature,
        last_valid_block_height: Option<u64>,
    ) -> Result<(), ClientError> {
        self.block_on(settle(
            self.rpc().client().get_inner_client(),
            &self.client.indexer,
            signature,
            last_valid_block_height,
            self.client.indexer_config.poll,
            WAIT_TIMEOUT,
        ))
    }
}

/// Photon persists every event of a transaction atomically. One visible event
/// therefore proves its private effects are indexed, even after the RPC cache
/// forgets it. An empty answer establishes expiry only after the indexer has
/// processed through the slot where we first observed a confirmed block height
/// beyond the saved last valid height.
///
/// Each round asks Solana and the indexer at once. A lookup that failed is
/// asked again next round. Permanent indexer errors end the wait as themselves.
async fn settle(
    rpc: &RpcClient,
    indexer: &impl AsyncRpc,
    signature: Signature,
    last_valid_block_height: Option<u64>,
    poll: IndexerPollConfig,
    timeout: Duration,
) -> Result<(), ClientError> {
    let (mut confirmed, mut expiry_slot, mut cause) = (false, None, None);
    let mut indexed = false;
    let result = tokio::time::timeout(timeout, async {
        for delay in std::iter::once(Duration::ZERO).chain(poll.backoff()) {
            tokio::time::sleep(delay).await;
            cause = None;
            let status_request = async {
                if confirmed {
                    return Ok(false);
                }
                let statuses = match rpc.get_signature_statuses_with_history(&[signature]).await {
                    Ok(response) => response.value,
                    Err(_) => {
                        cause = Some("Solana signature status lookup failed");
                        return Ok(false);
                    }
                };
                let [status] = statuses.as_slice() else {
                    cause = Some("invalid signature status response");
                    return Ok(false);
                };
                if let Some(status) = status {
                    if matches!(
                        status.confirmation_status,
                        Some(
                            TransactionConfirmationStatus::Confirmed
                                | TransactionConfirmationStatus::Finalized
                        )
                    ) {
                        if let Some(failure) = &status.err {
                            return Err(ClientError::SolanaRpcTransaction {
                                operation: "wait_for_private_transaction",
                                source: failure.clone().into(),
                            });
                        }
                        confirmed = true;
                    }
                    return Ok(false);
                }
                if let Some(height) = last_valid_block_height.filter(|_| expiry_slot.is_none()) {
                    match rpc
                        .get_epoch_info_with_commitment(CommitmentConfig::confirmed())
                        .await
                    {
                        Ok(bank) if bank.block_height > height => {
                            expiry_slot = Some(bank.absolute_slot);
                        }
                        Ok(_) => {}
                        Err(_) => {
                            cause = Some("Solana blockhash expiry lookup failed");
                            return Ok(false);
                        }
                    }
                }
                Ok(true)
            };
            let indexer_request = async {
                let found = indexer
                    .get_shielded_transactions_by_signature(signature, None)
                    .await
                    .and_then(|found| {
                        if let Some(other) = found
                            .transactions
                            .iter()
                            .find(|event| event.transaction.tx_signature != signature)
                        {
                            return Err(ClientError::Indexer(format!(
                                "getShieldedTransactionsBySignature({signature}) returned an event of transaction {}",
                                other.transaction.tx_signature
                            )));
                        }
                        indexed = !found.transactions.is_empty();
                        Ok(found)
                    });
                // Keep indexer errors as values so a confirmed chain failure
                // can take precedence and cancel a pending indexer request.
                Ok::<_, ClientError>(found)
            };
            let (found, signature_absent) = match tokio::try_join!(indexer_request, status_request) {
                Ok(results) => results,
                Err(failure) => return Some(Err(failure)),
            };
            match found {
                Ok(found) => {
                    if indexed {
                        return Some(Ok(()));
                    }
                    if signature_absent
                        && expiry_slot.is_some_and(|slot| found.context.slot >= slot)
                    {
                        return Some(Err(ClientError::TransactionExpired { signature }));
                    }
                }
                Err(failure) if indexer.should_retry(&failure) => {
                    cause = cause.or(Some("indexer lookup failed"));
                }
                Err(failure) => return Some(Err(failure)),
            }
        }
        None
    })
    .await;
    if let Ok(Some(result)) = result {
        return result;
    }
    // The indexer may have proved success while Solana's request remained
    // pending. A failure read before the deadline still wins above.
    if indexed {
        return Ok(());
    }
    let message = if result.is_err() {
        "transaction wait deadline elapsed"
    } else {
        cause.unwrap_or("the indexer does not have it yet")
    }
    .into();
    Err(if confirmed {
        ClientError::TransactionNotIndexed { signature, message }
    } else {
        ClientError::TransactionOutcomeUnknown { signature, message }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };

    use async_trait::async_trait;
    use serde_json::{json, Value};
    use solana_rpc_client::rpc_sender::{RpcSender, RpcTransportStats};
    use solana_rpc_client_api::{client_error, request::RpcRequest};
    use solana_transaction::TransactionError;

    use super::*;
    use crate::rpc::{
        Context, GetShieldedTransactionsBySignatureResponse, IndexedShieldedTransaction,
        ShieldedTransaction,
    };

    fn checkpoint_signature() -> Signature {
        Signature::from([3; 64])
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vector {
        name: String,
        last_valid_block_height: Option<u64>,
        rounds: Vec<Round>,
        outcome: String,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Round {
        status: String,
        failed: bool,
        height: u64,
        slot: u64,
        indexer_slot: u64,
        indexed: bool,
        indexer_error: bool,
    }

    impl Default for Round {
        fn default() -> Self {
            Self {
                status: "absent".into(),
                failed: false,
                height: 101,
                slot: 100,
                indexer_slot: 100,
                indexed: false,
                indexer_error: false,
            }
        }
    }

    #[derive(Default)]
    struct Fixture {
        rounds: Vec<Round>,
        status_reads: AtomicUsize,
        indexer_reads: AtomicUsize,
        hang_rpc: Option<RpcRequest>,
        hang_indexer: bool,
        indexer_cancelled: AtomicBool,
        wrong_signature: bool,
        fatal_indexer: bool,
    }

    impl Fixture {
        fn round(&self, index: usize) -> &Round {
            &self.rounds[index.min(self.rounds.len() - 1)]
        }

        async fn wait(self: &Arc<Self>, height: Option<u64>) -> Result<(), ClientError> {
            let rpc = RpcClient::new_sender(Transport(Arc::clone(self)), Default::default());
            settle(
                &rpc,
                self.as_ref(),
                checkpoint_signature(),
                height,
                IndexerPollConfig {
                    num_retries: (self.rounds.len() - 1) as u32,
                    delay_ms: 1,
                    max_delay_ms: 1,
                },
                Duration::from_millis(10),
            )
            .await
        }
    }

    /// Exercise Solana's native decoder and request encoding, not an SDK RPC facade.
    struct Transport(Arc<Fixture>);

    #[async_trait]
    impl RpcSender for Transport {
        async fn send(&self, request: RpcRequest, params: Value) -> client_error::Result<Value> {
            if self.0.hang_rpc == Some(request) {
                return std::future::pending().await;
            }
            match request {
                RpcRequest::GetSignatureStatuses => {
                    assert_eq!(
                        params,
                        json!([[checkpoint_signature().to_string()], {"searchTransactionHistory": true}])
                    );
                    let round = self
                        .0
                        .round(self.0.status_reads.fetch_add(1, Ordering::SeqCst));
                    let error = round
                        .failed
                        .then_some(TransactionError::InsufficientFundsForFee);
                    let status = match round.status.as_str() {
                        "absent" => Value::Null,
                        "rpcError" => {
                            return Err(client_error::ErrorKind::Custom("unavailable".into()).into())
                        }
                        _ => json!({
                            "slot": 42,
                            "confirmations": 1,
                            "status": error.clone().map_or(Ok(()), Err),
                            "err": error,
                            "confirmationStatus": if round.status == "missing" { None } else { Some(&round.status) },
                        }),
                    };
                    Ok(json!({
                        "context": {"slot": round.slot},
                        "value": if round.status == "invalid" { vec![] } else { vec![status] },
                    }))
                }
                RpcRequest::GetEpochInfo => {
                    assert_eq!(params, json!([{"commitment": "confirmed"}]));
                    let round = self.0.round(self.0.status_reads.load(Ordering::SeqCst) - 1);
                    Ok(json!({
                        "epoch": 0, "slotIndex": round.slot, "slotsInEpoch": 432_000,
                        "absoluteSlot": round.slot, "blockHeight": round.height,
                        "transactionCount": null,
                    }))
                }
                other => panic!("recovery must not invoke {other:?}"),
            }
        }

        fn get_transport_stats(&self) -> RpcTransportStats {
            RpcTransportStats::default()
        }

        fn url(&self) -> String {
            "http://localhost".into()
        }
    }

    struct Cancelled<'a>(&'a AtomicBool);

    impl Drop for Cancelled<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl AsyncRpc for Fixture {
        fn should_retry(&self, error: &ClientError) -> bool {
            matches!(error, ClientError::Rpc(_))
        }

        async fn get_shielded_transactions_by_signature(
            &self,
            signature: Signature,
            _: Option<crate::rpc::IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
            assert_eq!(signature, checkpoint_signature());
            let round = self.round(self.indexer_reads.fetch_add(1, Ordering::SeqCst));
            if self.hang_indexer {
                let _cancelled = Cancelled(&self.indexer_cancelled);
                return std::future::pending().await;
            }
            if self.fatal_indexer {
                return Err(ClientError::UnsupportedRpcMethod(
                    "getShieldedTransactionsBySignature",
                ));
            }
            if round.indexer_error {
                return Err(ClientError::Rpc("unavailable".into()));
            }
            Ok(GetShieldedTransactionsBySignatureResponse {
                context: Context {
                    block_time: 0,
                    slot: round.indexer_slot,
                },
                output_tree_id: None,
                transactions: if round.indexed {
                    vec![IndexedShieldedTransaction {
                        event_index: 0,
                        transaction: ShieldedTransaction {
                            slot: 42,
                            tx_signature: if self.wrong_signature {
                                Signature::from([4; 64])
                            } else {
                                signature
                            },
                            event_index: Some(0),
                            tx_viewing_pk: None,
                            salt: None,
                            output_slots: vec![],
                            messages: vec![],
                            nullifiers: vec![],
                            proofless: false,
                            ring_config: None,
                            ring_program_id: None,
                        },
                    }]
                } else {
                    vec![]
                },
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn matches_typescript_recovery_vectors() {
        let vectors: Vec<Vector> = serde_json::from_str(include_str!(
            "../../../../test-vectors/private_transaction_confirmation.json"
        ))
        .unwrap();
        for vector in vectors {
            let fixture = Arc::new(Fixture {
                rounds: vector.rounds,
                ..Fixture::default()
            });
            let outcome = match fixture.wait(vector.last_valid_block_height).await {
                Ok(()) => "indexed",
                Err(ClientError::TransactionExpired { .. }) => "expired",
                Err(ClientError::TransactionNotIndexed { .. }) => "notIndexed",
                Err(ClientError::TransactionOutcomeUnknown { .. }) => "unknown",
                Err(ClientError::SolanaRpcTransaction { source, .. }) => {
                    assert_eq!(
                        source.get_transaction_error(),
                        Some(TransactionError::InsufficientFundsForFee)
                    );
                    "failed"
                }
                other => panic!("unexpected outcome for {}: {other:?}", vector.name),
            };
            assert_eq!(outcome, vector.outcome, "{}", vector.name);
            assert_eq!(
                fixture.indexer_reads.load(Ordering::SeqCst),
                fixture.rounds.len(),
                "{}",
                vector.name
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn confirmed_failure_cancels_a_hung_indexer_immediately() {
        let fixture = Arc::new(Fixture {
            rounds: vec![Round {
                status: "confirmed".into(),
                failed: true,
                ..Round::default()
            }],
            hang_indexer: true,
            ..Fixture::default()
        });
        let started = tokio::time::Instant::now();
        assert!(matches!(
            fixture.wait(Some(100)).await,
            Err(ClientError::SolanaRpcTransaction { .. })
        ));
        assert!(started.elapsed() < Duration::from_millis(10));
        assert!(fixture.indexer_cancelled.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_bounds_hung_requests_and_preserves_only_valid_evidence() {
        for (rpc, indexer, indexed, wrong_signature, expected) in [
            (
                Some(RpcRequest::GetSignatureStatuses),
                false,
                false,
                false,
                "unknown",
            ),
            (
                Some(RpcRequest::GetEpochInfo),
                false,
                false,
                false,
                "unknown",
            ),
            (
                Some(RpcRequest::GetSignatureStatuses),
                false,
                true,
                false,
                "indexed",
            ),
            (
                Some(RpcRequest::GetSignatureStatuses),
                false,
                true,
                true,
                "unknown",
            ),
            (None, true, false, false, "notIndexed"),
        ] {
            let fixture = Arc::new(Fixture {
                rounds: vec![Round {
                    status: if indexer { "confirmed" } else { "absent" }.into(),
                    indexed,
                    ..Round::default()
                }],
                hang_rpc: rpc,
                hang_indexer: indexer,
                wrong_signature,
                ..Fixture::default()
            });
            let started = tokio::time::Instant::now();
            let result = fixture.wait(Some(100)).await;
            let outcome = match result {
                Ok(()) => "indexed",
                Err(ClientError::TransactionOutcomeUnknown { .. }) => "unknown",
                Err(ClientError::TransactionNotIndexed { .. }) => "notIndexed",
                other => panic!("unexpected deadline outcome: {other:?}"),
            };
            assert_eq!(outcome, expected);
            assert_eq!(started.elapsed(), Duration::from_millis(10));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn permanent_indexer_errors_and_mismatched_events_are_not_retried() {
        for wrong_signature in [false, true] {
            let fixture = Arc::new(Fixture {
                rounds: vec![
                    Round {
                        indexed: true,
                        ..Round::default()
                    },
                    Round::default(),
                ],
                wrong_signature,
                fatal_indexer: !wrong_signature,
                ..Fixture::default()
            });
            let error = fixture.wait(Some(100)).await.unwrap_err();
            assert!(if wrong_signature {
                matches!(error, ClientError::Indexer(_))
            } else {
                matches!(error, ClientError::UnsupportedRpcMethod(_))
            });
            assert_eq!(fixture.indexer_reads.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn confirmed_status_is_not_queried_again() {
        let fixture = Arc::new(Fixture {
            rounds: vec![
                Round {
                    status: "confirmed".into(),
                    ..Round::default()
                },
                Round::default(),
            ],
            ..Fixture::default()
        });
        assert!(matches!(
            fixture.wait(Some(100)).await,
            Err(ClientError::TransactionNotIndexed { .. })
        ));
        assert_eq!(fixture.status_reads.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.indexer_reads.load(Ordering::SeqCst), 2);
    }
}
