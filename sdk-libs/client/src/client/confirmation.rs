use std::time::Duration;

use solana_signature::Signature;
use solana_transaction_status_client_types::TransactionConfirmationStatus;

use crate::{
    error::ClientError,
    rpc::{AsyncRpc, IndexerPollConfig},
};

use super::{AsyncIndexer, AsyncSprClient, BlockingIndexer, BlockingRpc, SprClient};

impl<R: AsyncRpc, I: AsyncIndexer> AsyncSprClient<R, I> {
    /// Wait until Solana confirms the transaction and Photon has indexed a
    /// Rings event for it. Both waits poll on the client's
    /// [`IndexerPollConfig`] and retry a failed request.
    ///
    /// A transaction that failed on chain returns the chain's error as a
    /// [`ClientError::SolanaRpcTransaction`] as soon as the RPC reports it,
    /// instead of an indexer timeout that blames the wrong subsystem. Once
    /// Solana has confirmed the transaction, an indexer failure returns
    /// [`ClientError::TransactionNotIndexed`]: the transaction landed and
    /// must not be sent again.
    pub async fn confirm_private_transaction(
        &self,
        signature: Signature,
    ) -> Result<(), ClientError> {
        wait_for_rpc_confirmation(self.rpc(), signature, self.indexer_config.poll).await?;
        wait_for_indexed_transaction(&self.indexer, signature, self.indexer_config.poll)
            .await
            .map_err(|source| ClientError::TransactionNotIndexed {
                signature,
                source: Box::new(source),
            })
    }
}

impl<R: BlockingRpc, I: BlockingIndexer> SprClient<R, I> {
    /// See [`AsyncSprClient::confirm_private_transaction`].
    pub fn confirm_private_transaction_sync(
        &self,
        signature: Signature,
    ) -> Result<(), ClientError> {
        self.block_on(self.client.confirm_private_transaction(signature))
    }
}

/// Poll the RPC until the signature reaches confirmed commitment, and return
/// the chain's error if the transaction failed there. A failed status read is
/// retried, except from an RPC that does not implement the read.
async fn wait_for_rpc_confirmation<R: AsyncRpc>(
    rpc: &R,
    signature: Signature,
    retry: IndexerPollConfig,
) -> Result<(), ClientError> {
    let mut last_error = None;
    for delay in std::iter::once(Duration::ZERO).chain(retry.backoff()) {
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        match rpc.get_signature_statuses(vec![signature]).await {
            Ok(statuses) => {
                last_error = None;
                let confirmed = statuses.into_iter().next().flatten().filter(|status| {
                    status.confirmation_status() != TransactionConfirmationStatus::Processed
                });
                if let Some(status) = confirmed {
                    return match status.err {
                        None => Ok(()),
                        Some(failure) => Err(ClientError::SolanaRpcTransaction {
                            operation: "confirm_private_transaction",
                            source: failure.into(),
                        }),
                    };
                }
            }
            Err(error @ ClientError::UnsupportedRpcMethod(_)) => return Err(error),
            Err(error) => last_error = Some(error.to_string()),
        }
    }
    Err(poll_timeout(
        retry,
        last_error,
        ClientError::Rpc(format!("signature not confirmed: {signature}")),
    ))
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
    Err(poll_timeout(retry, last_error, ClientError::IndexerTimeout))
}

/// Classify an exhausted poll by how the *final* attempt went, since that is
/// the freshest evidence of what the service is doing now: an attempt that
/// answered without the transaction means it is behind (`behind`), and one
/// that failed means it never answered, which is not a lag report the caller
/// should act on. Earlier failures inside the window are deliberately not
/// reported -- a blip the service recovered from should not be blamed for a
/// genuine lag.
fn poll_timeout(
    retry: IndexerPollConfig,
    last_error: Option<String>,
    behind: ClientError,
) -> ClientError {
    match last_error {
        Some(last_error) => ClientError::PollTimedOut {
            attempts: retry.num_retries.saturating_add(1),
            last_error: Some(last_error),
        },
        None => behind,
    }
}
