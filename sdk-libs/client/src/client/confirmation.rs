use std::time::Duration;

use solana_signature::Signature;

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
}

impl<R: BlockingRpc, I: BlockingIndexer> ZolanaClient<R, I> {
    /// See [`AsyncZolanaClient::confirm_private_transaction`].
    pub fn confirm_private_transaction_sync(
        &self,
        signature: Signature,
    ) -> Result<(), ClientError> {
        self.block_on(self.client.confirm_private_transaction(signature))
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
