use std::time::Duration;

use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_error::TransactionError as ChainError;
use solana_transaction_status_client_types::{TransactionConfirmationStatus, TransactionStatus};

use crate::{
    error::ClientError,
    rpc::{AsyncRpc, IndexerPollConfig},
};

use super::{AsyncIndexer, AsyncZolanaClient, BlockingIndexer, BlockingRpc, ZolanaClient};

impl<R: AsyncRpc, I: AsyncIndexer> AsyncZolanaClient<R, I> {
    /// Wait until Solana confirms the transaction and Photon has indexed a
    /// Rings event for it.
    ///
    /// Confirming first turns a transaction that failed on chain into a chain
    /// error, instead of an indexer timeout that blames the wrong subsystem.
    pub async fn confirm_private_transaction(
        &self,
        signature: Signature,
    ) -> Result<(), ClientError> {
        wait_for_rpc_confirmation(self.rpc(), signature, self.indexer_config.poll).await?;
        wait_for_indexed_transaction(&self.indexer, signature, self.indexer_config.poll).await
    }

    /// Send `transaction`, a signed private transaction: a deposit, transfer
    /// or merge, which the indexer records once it succeeds. Then wait as
    /// [`Self::wait_for_private_transaction`] does. A send the chain refused
    /// fails at once; any other failed send may have landed, so it is waited
    /// for too.
    pub async fn submit_private_transaction(
        &self,
        transaction: VersionedTransaction,
        last_valid_block_height: u64,
    ) -> Result<Signature, ClientError> {
        let signature = *transaction.signatures.first().ok_or_else(|| {
            ClientError::SolanaTransactionSigning("the transaction is not signed".into())
        })?;
        if let Err(failure) = self.rpc.process_transaction(transaction).await {
            if refused(&failure) {
                return Err(failure);
            }
        }
        self.wait_for_private_transaction(signature, Some(last_valid_block_height))
            .await?;
        Ok(signature)
    }

    /// Wait for `signature`, a private transaction sent before, for at most
    /// the client's indexer poll schedule. It ends:
    ///
    /// - `Ok` once the indexer has it, so reads see its notes, with or without
    ///   `last_valid_block_height`;
    /// - with the chain's error once Solana confirms it failed;
    /// - [`ClientError::TransactionExpired`] once the RPC does not hold it,
    ///   its blockhash expired after `last_valid_block_height`, and the
    ///   indexer, at or past the slot where it expired, has no record of it;
    /// - [`ClientError::TransactionNotIndexed`] when Solana confirmed it but
    ///   the indexer did not record it in time;
    /// - [`ClientError::TransactionOutcomeUnknown`] otherwise. Waiting again
    ///   resumes.
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

    /// See [`AsyncZolanaClient::submit_private_transaction`].
    pub fn submit_private_transaction_sync(
        &self,
        transaction: VersionedTransaction,
        last_valid_block_height: u64,
    ) -> Result<Signature, ClientError> {
        self.block_on(
            self.client
                .submit_private_transaction(transaction, last_valid_block_height),
        )
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

/// Poll the RPC until the signature reaches confirmed commitment.
async fn wait_for_rpc_confirmation<R: AsyncRpc>(
    rpc: &R,
    signature: Signature,
    retry: IndexerPollConfig,
) -> Result<(), ClientError> {
    for delay in std::iter::once(Duration::ZERO).chain(retry.backoff()) {
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        if rpc.confirm_transaction(signature).await? {
            return Ok(());
        }
    }
    Err(ClientError::Rpc(format!(
        "signature not confirmed: {signature}"
    )))
}

/// Poll the indexer until it reports the transaction.
///
/// Photon writes every event of a transaction in one indexer slot inside one
/// database transaction, so a single visible event proves the whole transaction
/// is indexed. Matching the event against the transaction's view tags would add
/// no guarantee and would reject legitimate transactions whose events share a
/// tag.
async fn wait_for_indexed_transaction<I: AsyncRpc>(
    indexer: &I,
    signature: Signature,
    retry: IndexerPollConfig,
) -> Result<(), ClientError> {
    let mut last_error = None;
    for delay in std::iter::once(Duration::ZERO).chain(retry.backoff()) {
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        match indexer
            .get_shielded_transactions_by_signature(signature, None)
            .await
        {
            Ok(response) if !response.transactions.is_empty() => return Ok(()),
            Ok(_) => last_error = None,
            Err(error) if indexer.should_retry(&error) => last_error = Some(error.to_string()),
            Err(error) => return Err(error),
        }
    }
    Err(indexer_poll_timeout(retry, last_error))
}

/// Classify an exhausted poll by how the *final* attempt went, since that is
/// the freshest evidence of what the indexer is doing now: an attempt that
/// answered without the transaction means the indexer is behind, and one that
/// failed means it never answered, which is not a lag report the caller should
/// act on. Earlier failures inside the window are deliberately not reported --
/// a blip the indexer recovered from should not be blamed for a genuine lag.
fn indexer_poll_timeout(retry: IndexerPollConfig, last_error: Option<String>) -> ClientError {
    match last_error {
        Some(last_error) => ClientError::PollTimedOut {
            attempts: retry.num_retries.saturating_add(1),
            last_error: Some(last_error),
        },
        None => ClientError::IndexerTimeout,
    }
}

/// Whether the chain refused `failure`'s transaction, in simulation or after
/// it ran, so it never succeeded. A simulation that found it already
/// processed is no refusal: it may have landed.
fn refused(failure: &ClientError) -> bool {
    matches!(failure, ClientError::SolanaRpcTransaction { source, .. }
    if !matches!(
        source.get_transaction_error(),
        None | Some(ChainError::AlreadyProcessed)
    ))
}

/// [`AsyncZolanaClient::wait_for_private_transaction`] over `rpc` and
/// `indexer`. Each round reads the status cache, the expiry once the cache
/// lacks the transaction, then the indexer.
async fn settle(
    rpc: &impl AsyncRpc,
    indexer: &impl AsyncRpc,
    signature: Signature,
    last_valid_block_height: Option<u64>,
    poll: IndexerPollConfig,
) -> Result<(), ClientError> {
    let (mut confirmed, mut expired_at, mut error) = (false, None, None);
    for delay in std::iter::once(Duration::ZERO).chain(poll.backoff()) {
        tokio::time::sleep(delay).await;
        let mut unseen = false;
        match rpc.get_signature_statuses(vec![signature]).await {
            Ok(statuses) => match statuses.into_iter().next().flatten() {
                Some(status) if is_confirmed(&status) => match status.err {
                    Some(failure) => {
                        return Err(ClientError::SolanaRpcTransaction {
                            operation: "process_transaction",
                            source: failure.into(),
                        })
                    }
                    None => confirmed = true,
                },
                Some(_) => {}
                None => unseen = !confirmed,
            },
            Err(failure) => error = Some(failure.to_string()),
        }
        if unseen && expired_at.is_none() {
            match expiry_slot(rpc, last_valid_block_height).await {
                Ok(slot) => expired_at = slot,
                Err(failure) => error = Some(failure.to_string()),
            }
        }
        match indexer
            .get_shielded_transactions_by_signature(signature, None)
            .await
        {
            Ok(found) if !found.transactions.is_empty() => return Ok(()),
            Ok(found) if unseen && expired_at.is_some_and(|slot| found.context.slot >= slot) => {
                return Err(ClientError::TransactionExpired { signature })
            }
            Ok(_) => {}
            Err(failure) => error = Some(failure.to_string()),
        }
    }
    let message = error.unwrap_or_else(|| "the indexer does not have it yet".into());
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

/// Whether `status` is at confirmed commitment or beyond, as Solana's
/// `TransactionStatus::satisfies_commitment` tells it.
fn is_confirmed(status: &TransactionStatus) -> bool {
    match &status.confirmation_status {
        Some(level) => *level != TransactionConfirmationStatus::Processed,
        None => status.confirmations.is_none_or(|count| count > 1),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;

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
        settle(chain, chain, Signature::from([3; 64]), height, QUICK).await
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

    /// A send refused in simulation never ran; one found already processed
    /// may have landed.
    #[test]
    fn only_a_refusal_ends_a_failed_send() {
        let preflight = |err: &str| {
            let result: solana_rpc_client_api::response::RpcSimulateTransactionResult =
                serde_json::from_str(&format!(r#"{{"err":"{err}"}}"#)).unwrap();
            ClientError::SolanaRpcTransaction {
                operation: "process_transaction",
                source: solana_rpc_client_api::request::RpcError::RpcResponseError {
                    code: -32002,
                    message: "Transaction simulation failed".into(),
                    data: solana_rpc_client_api::request::RpcResponseErrorData::SendTransactionPreflightFailure(result),
                }
                .into(),
            }
        };
        assert!(refused(&preflight("InsufficientFundsForFee")));
        assert!(!refused(&preflight("AlreadyProcessed")));
        assert!(!refused(&ClientError::Rpc("connection reset".into())));
    }
}
