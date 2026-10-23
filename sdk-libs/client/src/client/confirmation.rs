use std::time::Duration;

use solana_signature::Signature;
use solana_transaction_status_client_types::TransactionConfirmationStatus;

use crate::{
    error::ClientError,
    rpc::{AsyncRpc, IndexerPollConfig},
};

use super::{AsyncIndexer, AsyncZolanaClient, BlockingIndexer, BlockingRpc, ZolanaClient};

impl<R: AsyncRpc, I: AsyncIndexer> AsyncZolanaClient<R, I> {
    /// Wait for a private transaction's indexed effects using the same bounded
    /// recovery rules as [`Self::wait_for_private_transaction`], without an
    /// expiry height. This can return `TransactionNotIndexed` or
    /// `TransactionOutcomeUnknown`; neither permits rebuilding the transaction.
    pub async fn confirm_private_transaction(
        &self,
        signature: Signature,
    ) -> Result<(), ClientError> {
        self.wait_for_private_transaction(signature, None).await
    }

    /// Recover a previously sent deposit, transfer, withdrawal or merge by its
    /// signature. Never signs, sends or rebuilds a transaction.
    ///
    /// Returns `Ok` once the indexer has its private event, including when the
    /// signature has left Solana's recent status cache. A confirmed on-chain
    /// failure returns the chain error. Otherwise:
    ///
    /// - [`ClientError::TransactionExpired`]: the signature is absent, the
    ///   block height passed `last_valid_block_height`, and the indexer has
    ///   persisted through a slot sampled after expiry without its event;
    /// - [`ClientError::TransactionNotIndexed`]: confirmed on chain, but not
    ///   indexed before the wait ended;
    /// - [`ClientError::TransactionOutcomeUnknown`]: insufficient evidence.
    ///
    /// The indexer must index every private event on the same network as the
    /// RPC. Registration, arbitrary program calls and durable-nonce transactions
    /// are outside this contract. Persist the signed transaction's signature and
    /// last valid block height before sending; only `TransactionExpired` permits
    /// rebuilding after an ambiguous send. Other unresolved outcomes can be
    /// queried again with the same signature.
    ///
    /// Stops at the client's poll limit or transaction wait timeout (60 seconds
    /// by default), including time spent in requests. A blocking RPC adapter's
    /// underlying request may continue after this method returns.
    pub async fn wait_for_private_transaction(
        &self,
        signature: Signature,
        last_valid_block_height: Option<u64>,
    ) -> Result<(), ClientError> {
        settle(
            &self.rpc,
            &self.indexer,
            signature,
            last_valid_block_height,
            self.indexer_config.poll,
            self.transaction_wait_timeout,
        )
        .await
    }
}

impl<R: BlockingRpc, I: BlockingIndexer> ZolanaClient<R, I> {
    /// See [`AsyncZolanaClient::confirm_private_transaction`].
    pub fn confirm_private_transaction_sync(
        &self,
        signature: Signature,
    ) -> Result<(), ClientError> {
        self.block_on(self.client.confirm_private_transaction(signature))
    }

    /// See [`AsyncZolanaClient::wait_for_private_transaction`].
    pub fn wait_for_private_transaction_sync(
        &self,
        signature: Signature,
        last_valid_block_height: Option<u64>,
    ) -> Result<(), ClientError> {
        self.block_on(
            self.client
                .wait_for_private_transaction(signature, last_valid_block_height),
        )
    }
}

/// Photon persists every event of a transaction atomically. One visible event
/// therefore proves its private effects are indexed, even after the RPC cache
/// forgets it. An empty answer is evidence only after the expiry watermark.
async fn settle(
    rpc: &impl AsyncRpc,
    indexer: &impl AsyncRpc,
    signature: Signature,
    last_valid_block_height: Option<u64>,
    poll: IndexerPollConfig,
    timeout: Duration,
) -> Result<(), ClientError> {
    let (mut confirmed, mut expired_at, mut error) = (false, None, None);
    let result = tokio::time::timeout(timeout, async {
        for delay in std::iter::once(Duration::ZERO).chain(poll.backoff()) {
            tokio::time::sleep(delay).await;
            let mut unseen = false;
            match rpc.get_signature_statuses(vec![signature]).await {
                Ok(statuses) if statuses.len() != 1 => {
                    error = Some("invalid signature status response");
                    return None;
                }
                Ok(statuses) => match statuses.into_iter().next().flatten() {
                    Some(status)
                        if matches!(
                            status.confirmation_status,
                            Some(
                                TransactionConfirmationStatus::Confirmed
                                    | TransactionConfirmationStatus::Finalized
                            )
                        ) =>
                    {
                        match status.err {
                            Some(failure) => {
                                return Some(Err(ClientError::SolanaRpcTransaction {
                                    operation: "process_transaction",
                                    source: failure.into(),
                                }))
                            }
                            None => confirmed = true,
                        }
                    }
                    // A missing confirmationStatus is not proof of confirmation.
                    Some(_) => {}
                    None => unseen = !confirmed,
                },
                Err(_) => error = Some("Solana signature status lookup failed"),
            }
            if unseen && expired_at.is_none() {
                match expiry_slot(rpc, last_valid_block_height).await {
                    Ok(slot) => expired_at = slot,
                    Err(_) => error = Some("Solana blockhash expiry lookup failed"),
                }
            }
            match indexer
                .get_shielded_transactions_by_signature(signature, None)
                .await
            {
                Ok(found)
                    if found
                        .transactions
                        .iter()
                        .any(|event| event.transaction.tx_signature != signature) =>
                {
                    error = Some("indexer returned another transaction's event");
                    return None;
                }
                Ok(found) if !found.transactions.is_empty() => return Some(Ok(())),
                Ok(found)
                    if unseen && expired_at.is_some_and(|slot| found.context.slot >= slot) =>
                {
                    return Some(Err(ClientError::TransactionExpired { signature }))
                }
                Ok(_) => error = None,
                Err(failure) => {
                    error = Some("indexer lookup failed");
                    if !indexer.should_retry(&failure) {
                        return None;
                    }
                }
            }
        }
        None
    })
    .await;
    if let Ok(Some(result)) = result {
        return result;
    }
    let message = if result.is_err() {
        "transaction wait deadline elapsed"
    } else {
        error.unwrap_or("the indexer does not have it yet")
    }
    .into();
    Err(if confirmed {
        ClientError::TransactionNotIndexed { signature, message }
    } else {
        ClientError::TransactionOutcomeUnknown { signature, message }
    })
}

/// The RPC's slot once its block height passed `last_valid_block_height`: a
/// transaction with that blockhash landed by then or never will.
async fn expiry_slot(
    rpc: &impl AsyncRpc,
    last_valid_block_height: Option<u64>,
) -> Result<Option<u64>, ClientError> {
    match last_valid_block_height {
        Some(height) if rpc.get_block_height().await? > height => Ok(Some(rpc.get_slot().await?)),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use solana_transaction::TransactionError as ChainError;
    use solana_transaction_status_client_types::TransactionStatus;

    use super::*;
    use crate::rpc::{
        Context, GetShieldedTransactionsBySignatureResponse, IndexedShieldedTransaction,
        ShieldedTransaction,
    };

    /// A Solana RPC and its indexer: the status cache holds `status`, the
    /// block height stays `height` and the slot 100; the indexer, at
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

    #[async_trait]
    impl AsyncRpc for Chain {
        async fn get_block_height(&self) -> Result<u64, ClientError> {
            Ok(self.height)
        }

        async fn get_slot(&self) -> Result<u64, ClientError> {
            Ok(100)
        }

        async fn get_signature_statuses(
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

        let behind = Chain {
            indexer_slot: 99,
            ..Chain::new(None, 101)
        };
        assert!(matches!(
            settled(&behind, Some(100)).await,
            Err(ClientError::TransactionOutcomeUnknown { .. })
        ));
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

    struct ScriptedChain {
        rounds: Vec<RecoveryRound>,
        reads: Mutex<usize>,
    }

    impl ScriptedChain {
        fn round(&self) -> &RecoveryRound {
            &self.rounds[self.reads.lock().unwrap().saturating_sub(1)]
        }
    }

    #[async_trait]
    impl AsyncRpc for ScriptedChain {
        fn should_retry(&self, _: &ClientError) -> bool {
            true
        }

        async fn get_signature_statuses(
            &self,
            _: Vec<Signature>,
        ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
            *self.reads.lock().unwrap() += 1;
            let round = self.round();
            match round.status.as_str() {
                "absent" => Ok(vec![None]),
                "rpcError" => Err(ClientError::Rpc("unavailable".into())),
                "invalid" => Ok(vec![]),
                _ => {
                    let mut status =
                        landed(round.failed.then_some(ChainError::InsufficientFundsForFee))
                            .unwrap();
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
        async fn get_block_height(&self) -> Result<u64, ClientError> {
            Ok(self.round().height)
        }
        async fn get_slot(&self) -> Result<u64, ClientError> {
            Ok(self.round().slot)
        }
        async fn get_shielded_transactions_by_signature(
            &self,
            signature: Signature,
            _: Option<crate::rpc::IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
            let round = self.round();
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
            "../../../../test-vectors/private_transaction_confirmation.json"
        ))
        .unwrap();
        for vector in vectors {
            let attempts = vector.rounds.len();
            let chain = ScriptedChain {
                rounds: vector.rounds,
                reads: Mutex::new(0),
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
            assert_eq!(*chain.reads.lock().unwrap(), attempts, "{}", vector.name);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_bounds_a_hung_rpc_without_claiming_expiry() {
        struct HungRpc;
        #[async_trait]
        impl AsyncRpc for HungRpc {
            async fn get_signature_statuses(
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
        assert!(matches!(
            settle(
                &chain,
                &WrongSignature,
                Signature::from([3; 64]),
                Some(100),
                QUICK,
                Duration::from_secs(60)
            )
            .await,
            Err(ClientError::TransactionOutcomeUnknown { .. })
        ));
        assert_eq!(*chain.lookups.lock().unwrap(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn permanent_indexer_failure_stops_without_losing_confirmation() {
        struct InvalidIndexer;
        #[async_trait]
        impl AsyncRpc for InvalidIndexer {
            async fn get_shielded_transactions_by_signature(
                &self,
                _: Signature,
                _: Option<crate::rpc::IndexerRpcConfig>,
            ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
                Err(ClientError::Rpc("secret invalid response body".into()))
            }
        }
        let chain = Chain::new(landed(None), 101);
        let result = settle(
            &chain,
            &InvalidIndexer,
            Signature::from([3; 64]),
            Some(100),
            QUICK,
            Duration::from_secs(60),
        )
        .await;
        assert!(
            matches!(result, Err(ClientError::TransactionNotIndexed { message, .. }) if message == "indexer lookup failed")
        );
        assert_eq!(*chain.lookups.lock().unwrap(), 1);
    }
}
