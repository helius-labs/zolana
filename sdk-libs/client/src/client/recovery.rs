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
    /// is absent, its blockhash expired, and the indexer persisted through the
    /// confirmed bank that proved expiry without its event. Only that outcome
    /// permits rebuilding after an ambiguous send.
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
/// forgets it. An empty answer is evidence only after the expiry watermark.
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
    let (mut confirmed, mut expired_at, mut cause) = (false, None, None);
    let mut indexed = false;
    let result = tokio::time::timeout(timeout, async {
        for delay in std::iter::once(Duration::ZERO).chain(poll.backoff()) {
            tokio::time::sleep(delay).await;
            // A confirmed chain failure ends the round immediately, dropping
            // a still-pending indexer request. Indexer errors remain values so
            // they cannot prevent the chain from establishing its outcome.
            let round = tokio::try_join!(
                async {
                    Ok::<_, ClientError>(
                        indexer
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
                            }),
                    )
                },
                chain_round(
                    rpc,
                    signature,
                    last_valid_block_height,
                    &mut confirmed,
                    &mut expired_at,
                ),
            );
            let (found, chain) = match round {
                Ok(round) => round,
                Err(failure) => return Some(Err(failure)),
            };
            cause = chain.cause;
            match found {
                Ok(found) => {
                    if indexed {
                        return Some(Ok(()));
                    }
                    if chain.unseen && expired_at.is_some_and(|slot| found.context.slot >= slot) {
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

/// What one round learned from Solana, short of a confirmed failure.
#[derive(Default)]
struct ChainRound {
    /// Neither the status cache nor the ledger holds the signature.
    unseen: bool,
    /// A lookup failed this round; the next round asks again.
    cause: Option<&'static str>,
}

/// One history-enabled status read covers both recent sends and restart
/// recovery. Transport failures are values; a confirmed chain failure is an
/// error, so it ends the wait even while the indexer request is still pending.
async fn chain_round(
    rpc: &RpcClient,
    signature: Signature,
    last_valid_block_height: Option<u64>,
    confirmed: &mut bool,
    expired_at: &mut Option<u64>,
) -> Result<ChainRound, ClientError> {
    if *confirmed {
        return Ok(ChainRound::default());
    }
    let statuses = match rpc.get_signature_statuses_with_history(&[signature]).await {
        Ok(response) => response.value,
        Err(_) => {
            return Ok(ChainRound {
                cause: Some("Solana signature status lookup failed"),
                ..ChainRound::default()
            })
        }
    };
    let [status] = statuses.as_slice() else {
        return Ok(ChainRound {
            cause: Some("invalid signature status response"),
            ..ChainRound::default()
        });
    };
    if let Some(status) = status {
        if matches!(
            status.confirmation_status,
            Some(
                TransactionConfirmationStatus::Confirmed | TransactionConfirmationStatus::Finalized
            )
        ) {
            if let Some(failure) = &status.err {
                return Err(ClientError::SolanaRpcTransaction {
                    operation: "wait_for_private_transaction",
                    source: failure.clone().into(),
                });
            }
            // Record evidence immediately, before waiting for the indexer.
            *confirmed = true;
        }
        return Ok(ChainRound::default());
    }
    if let Some(height) = last_valid_block_height.filter(|_| expired_at.is_none()) {
        match rpc
            .get_epoch_info_with_commitment(CommitmentConfig::confirmed())
            .await
        {
            Ok(bank) if bank.block_height > height => *expired_at = Some(bank.absolute_slot),
            Ok(_) => {}
            Err(_) => {
                return Ok(ChainRound {
                    cause: Some("Solana blockhash expiry lookup failed"),
                    ..ChainRound::default()
                })
            }
        }
    }
    Ok(ChainRound {
        unseen: true,
        ..ChainRound::default()
    })
}

#[cfg(test)]
mod tests;
