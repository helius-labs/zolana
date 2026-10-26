use std::time::Duration;

use solana_commitment_config::CommitmentLevel;
use solana_rpc_client_api::config::RpcSendTransactionConfig;
use solana_rpc_client_api::{client_error::ErrorKind, request::RpcError};
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
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
    /// failure returns the chain error, found in the RPC's ledger as well as
    /// its recent cache. Otherwise:
    ///
    /// - [`ClientError::TransactionExpired`]: the signature is absent, the
    ///   block height passed `last_valid_block_height`, and the indexer has
    ///   persisted through the slot of the bank that reported that height
    ///   without its event;
    /// - [`ClientError::TransactionNotIndexed`]: confirmed on chain, but not
    ///   indexed before the wait ended;
    /// - [`ClientError::TransactionOutcomeUnknown`]: insufficient evidence.
    ///
    /// A failure that waiting cannot fix ends the wait as itself: an adapter
    /// without a lookup this needs ([`ClientError::UnsupportedRpcMethod`]),
    /// an indexer error its adapter does not retry, or an indexer answering
    /// with another transaction's event. Keep the checkpoint, fix the
    /// service, and wait again.
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
    /// Indexed evidence received before the deadline still proves success if
    /// the RPC never answers; a confirmed chain failure read before it takes
    /// precedence.
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

    /// Send a signed deposit, transfer, withdrawal or merge and wait for its
    /// private effects. A send that lost its connection may still have
    /// broadcast the transaction, so its outcome is recovered by signature
    /// rather than reported as a failure the caller would retry; an unresolved
    /// outcome carries the signature to wait on again.
    pub(super) async fn send_private_transaction(
        &self,
        transaction: VersionedTransaction,
        last_valid_block_height: u64,
    ) -> Result<Signature, ClientError> {
        let signature = *transaction.signatures.first().ok_or_else(|| {
            ClientError::SolanaTransactionSigning("the transaction carries no signature".into())
        })?;
        // Only classify the broadcast's error: a combined send-and-confirm
        // adapter can fail a later lookup after the transaction was accepted.
        if let Err(error) = self
            .send_transaction_with_config(
                &transaction,
                RpcSendTransactionConfig {
                    preflight_commitment: Some(CommitmentLevel::Confirmed),
                    ..RpcSendTransactionConfig::default()
                },
            )
            .await
        {
            if !may_have_landed(&error) {
                return Err(error);
            }
        }
        self.wait_for_private_transaction(signature, Some(last_valid_block_height))
            .await
            .map_err(|source| match source {
                // Keep the established outcome variants, which already name
                // the transaction. Other failures must retain recovery data.
                ClientError::TransactionExpired { .. }
                | ClientError::TransactionNotIndexed { .. }
                | ClientError::TransactionOutcomeUnknown { .. } => source,
                source => ClientError::PrivateTransactionRecoveryFailed {
                    signature,
                    last_valid_block_height,
                    source: Box::new(source),
                },
            })?;
        Ok(signature)
    }
}

/// Whether a failed send can still land: the request or its answer was lost
/// after the connection opened. A JSON-RPC error or an HTTP 4xx answer means
/// the RPC refused the request; a chain failure or a connection that never
/// opened also settles that it did not land.
fn may_have_landed(error: &ClientError) -> bool {
    let ClientError::SolanaRpcTransaction { source, .. } = error else {
        return false;
    };
    match source.kind() {
        ErrorKind::Reqwest(error) => {
            !error.is_connect()
                && !error
                    .status()
                    .is_some_and(|status| status.is_client_error())
        }
        ErrorKind::RpcError(RpcError::RpcResponseError { .. })
        | ErrorKind::SigningError(_)
        | ErrorKind::TransactionError(_) => false,
        ErrorKind::RpcError(_)
        | ErrorKind::Io(_)
        | ErrorKind::Middleware(_)
        | ErrorKind::SerdeJson(_)
        | ErrorKind::Custom(_) => true,
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
///
/// Each round asks Solana and the indexer at once. A lookup that failed is
/// asked again next round, unless waiting cannot fix it: an adapter without
/// the method, or an indexer error its adapter does not retry. That error ends
/// the wait as itself, after the round's indexer answer had its chance to
/// prove success.
async fn settle(
    rpc: &impl AsyncRpc,
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
                        indexer.get_shielded_transactions_by_signature(signature, None).await
                            .and_then(|found| {
                                if let Some(other) = found.transactions.iter().find(|event| event.transaction.tx_signature != signature) {
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
            if let Some(unsupported) = chain.unsupported {
                return Some(Err(unsupported));
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
    /// A lookup the RPC adapter does not implement, which no round can answer.
    unsupported: Option<ClientError>,
}

impl ChainRound {
    fn unavailable(error: ClientError, cause: &'static str) -> Self {
        Self {
            cause: Some(cause),
            unsupported: matches!(error, ClientError::UnsupportedRpcMethod(_)).then_some(error),
            ..Self::default()
        }
    }
}

/// One history-enabled status read covers both recent sends and restart
/// recovery. Transport failures are values; a confirmed chain failure is an
/// error, so it ends the wait even while the indexer request is still pending.
async fn chain_round(
    rpc: &impl AsyncRpc,
    signature: Signature,
    last_valid_block_height: Option<u64>,
    confirmed: &mut bool,
    expired_at: &mut Option<u64>,
) -> Result<ChainRound, ClientError> {
    if *confirmed {
        return Ok(ChainRound::default());
    }
    let statuses = match rpc
        .get_signature_statuses_with_history(vec![signature])
        .await
    {
        Ok(statuses) => statuses,
        Err(error) => {
            return Ok(ChainRound::unavailable(
                error,
                "Solana signature status lookup failed",
            ))
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
                    operation: "process_transaction",
                    source: failure.clone().into(),
                });
            }
            // Record evidence immediately, before waiting for the indexer.
            *confirmed = true;
        }
        return Ok(ChainRound::default());
    }
    if let Some(height) = last_valid_block_height.filter(|_| expired_at.is_none()) {
        match rpc.get_epoch_info().await {
            Ok(bank) if bank.block_height > height => *expired_at = Some(bank.absolute_slot),
            Ok(_) => {}
            Err(error) => {
                return Ok(ChainRound::unavailable(
                    error,
                    "Solana blockhash expiry lookup failed",
                ))
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
