use std::time::Duration;

use solana_message::VersionedMessage;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_error::TransactionError as ChainError;
use solana_transaction_status_client_types::{TransactionConfirmationStatus, TransactionStatus};
use zolana_interface::PROGRAM_ID_PUBKEY;

use crate::{
    error::ClientError,
    rpc::{AsyncRpc, IndexerPollConfig, IndexerRpcConfig},
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

    /// Send `transaction`, signed, and wait until its outcome is known: done
    /// once Solana confirms it and, when it calls the shielded pool, the
    /// indexer has it. `last_valid_block_height` is the last block height its
    /// blockhash lets it land at.
    ///
    /// A send that fails after the transaction may have gone out, such as one
    /// whose confirmation the RPC lost, is looked up as
    /// [`Self::wait_for_private_transaction`] looks one up. Fails with the
    /// chain's error when the chain refused it, in simulation or after it
    /// ran; [`ClientError::TransactionExpired`] when it can no longer land, so
    /// sending it again is safe; and [`ClientError::TransactionOutcomeUnknown`]
    /// when that cannot be told, so it may still land.
    pub async fn submit_transaction(
        &self,
        transaction: VersionedTransaction,
        last_valid_block_height: u64,
    ) -> Result<Signature, ClientError> {
        let signature = *transaction.signatures.first().ok_or_else(|| {
            ClientError::SolanaTransactionSigning("the transaction is not signed".into())
        })?;
        let indexed = calls_shielded_pool(&transaction.message);
        match self.rpc.process_transaction(transaction).await {
            Ok(_) => {}
            Err(failure) if settles_the_send(&failure) => return Err(failure),
            Err(_) => {
                reconcile(
                    self,
                    signature,
                    Some(last_valid_block_height),
                    indexed,
                    self.indexer_config.poll,
                )
                .await?
            }
        }
        if indexed {
            wait_for_indexed_transaction(&self.indexer, signature, self.indexer_config.poll)
                .await?;
        }
        Ok(signature)
    }

    /// Wait for `signature`, a shielded-pool transaction sent before, such as
    /// one sent before the application restarted, until its outcome is known:
    /// done once Solana confirms it and the indexer has it; the chain's error
    /// when the chain refused it; [`ClientError::TransactionExpired`] when it
    /// did not land before `last_valid_block_height`, so sending it again is
    /// safe; and [`ClientError::TransactionOutcomeUnknown`] when that cannot be
    /// told. Without `last_valid_block_height`, a transaction never seen
    /// cannot be told expired and ends unknown.
    ///
    /// The RPC's status cache holds recent transactions only, so one waited
    /// for long after it was sent may be gone from it though it landed. Past
    /// `last_valid_block_height`, a transaction the cache does not hold is
    /// looked for at the indexer once the indexer has reached the RPC's slot:
    /// it is expired only when the indexer does not have it. Once it is found,
    /// only the indexer is waited for.
    pub async fn wait_for_private_transaction(
        &self,
        signature: Signature,
        last_valid_block_height: Option<u64>,
    ) -> Result<(), ClientError> {
        reconcile(
            self,
            signature,
            last_valid_block_height,
            true,
            self.indexer_config.poll,
        )
        .await?;
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

    /// See [`AsyncZolanaClient::submit_transaction`].
    pub fn submit_transaction_sync(
        &self,
        transaction: VersionedTransaction,
        last_valid_block_height: u64,
    ) -> Result<Signature, ClientError> {
        self.block_on(
            self.client
                .submit_transaction(transaction, last_valid_block_height),
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

/// Whether `failure` settles a send: the chain ran the transaction and refused
/// it, or refused it in simulation, so it was never sent. A simulation that
/// found it already processed does not settle it, since it may have landed;
/// nor does any other failure, which may have come after the transaction went
/// out.
fn settles_the_send(failure: &ClientError) -> bool {
    matches!(failure, ClientError::SolanaRpcTransaction { source, .. }
    if !matches!(
        source.get_transaction_error(),
        None | Some(ChainError::AlreadyProcessed)
    ))
}

/// Whether `message` calls the shielded pool, whose transactions the indexer
/// records once they land.
fn calls_shielded_pool(message: &VersionedMessage) -> bool {
    let keys = message.static_account_keys();
    message.instructions().iter().any(|instruction| {
        keys.get(usize::from(instruction.program_id_index)) == Some(&PROGRAM_ID_PUBKEY)
    })
}

/// What a status lookup says of a transaction whose send went unanswered.
enum SendStatus {
    /// Landed and confirmed, without an error.
    Confirmed,
    /// Landed and confirmed, and the chain refused it.
    Refused(ChainError),
    /// Landed but not confirmed yet: it may still be dropped with its fork.
    Processed,
    /// Not seen, and its blockhash still lets it land.
    Pending,
    /// Not seen, and its blockhash no longer lets it land.
    Expired,
}

/// What became of `signature`, whose send went unanswered: looked up until it
/// is confirmed, refused by the chain or expired, at the indexer too when
/// `indexed`, as [`send_status`] says. Lookups that fail one after another, an
/// indexer that stays behind, a landed transaction that does not confirm,
/// and, without `last_valid_block_height`, one never seen, end after `poll`'s
/// retries as [`ClientError::TransactionOutcomeUnknown`].
async fn reconcile<C: AsyncRpc>(
    client: &C,
    signature: Signature,
    last_valid_block_height: Option<u64>,
    indexed: bool,
    poll: IndexerPollConfig,
) -> Result<(), ClientError> {
    let unknown = |message: String| ClientError::TransactionOutcomeUnknown { signature, message };
    let mut delays = poll
        .backoff()
        .chain(std::iter::repeat(Duration::from_millis(poll.max_delay_ms)));
    let (mut failed_lookups, mut processed_lookups, mut unseen_lookups) = (0, 0, 0);
    loop {
        match send_status(client, signature, last_valid_block_height, indexed, poll).await {
            Ok(SendStatus::Confirmed) => return Ok(()),
            Ok(SendStatus::Refused(failure)) => {
                return Err(ClientError::SolanaRpcTransaction {
                    operation: "process_transaction",
                    source: failure.into(),
                })
            }
            Ok(SendStatus::Expired) => return Err(ClientError::TransactionExpired { signature }),
            Ok(SendStatus::Pending) => {
                failed_lookups = 0;
                unseen_lookups += 1;
                if last_valid_block_height.is_none() && unseen_lookups > poll.num_retries {
                    return Err(unknown(
                        "not seen, and without its last valid block height it cannot be told expired"
                            .to_string(),
                    ));
                }
            }
            Ok(SendStatus::Processed) => {
                failed_lookups = 0;
                processed_lookups += 1;
                if processed_lookups > poll.num_retries {
                    return Err(unknown("landed but not confirmed".to_string()));
                }
            }
            Err(failure) => {
                failed_lookups += 1;
                if failed_lookups > poll.num_retries {
                    return Err(unknown(failure.to_string()));
                }
            }
        }
        tokio::time::sleep(delays.next().unwrap_or_default()).await;
    }
}

/// One look at `signature` in the RPC's status cache. The cache holds recent
/// transactions only, so past `last_valid_block_height` a shielded-pool
/// transaction (`indexed`) it lacks is looked for at the indexer, which has
/// every one that landed; the indexer is read once it has reached the RPC's
/// slot, waiting on `poll`'s schedule. Any other is expired.
async fn send_status<C: AsyncRpc>(
    client: &C,
    signature: Signature,
    last_valid_block_height: Option<u64>,
    indexed: bool,
    poll: IndexerPollConfig,
) -> Result<SendStatus, ClientError> {
    let status = client
        .get_signature_statuses(vec![signature])
        .await?
        .into_iter()
        .next()
        .flatten();
    if let Some(status) = status {
        return Ok(match (is_confirmed(&status), status.err) {
            (false, _) => SendStatus::Processed,
            (true, None) => SendStatus::Confirmed,
            (true, Some(failure)) => SendStatus::Refused(failure),
        });
    }
    let expired = match last_valid_block_height {
        Some(height) => client.get_block_height().await? > height,
        None => false,
    };
    if !expired {
        return Ok(SendStatus::Pending);
    }
    if indexed {
        let config = IndexerRpcConfig {
            poll,
            require_slot: Some(client.get_slot().await?),
        };
        let found = client
            .get_shielded_transactions_by_signature(signature, Some(config))
            .await?;
        if !found.transactions.is_empty() {
            return Ok(SendStatus::Confirmed);
        }
    }
    Ok(SendStatus::Expired)
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
    use std::{collections::VecDeque, sync::Mutex};

    use async_trait::async_trait;
    use solana_hash::Hash;
    use solana_instruction::Instruction;
    use solana_pubkey::Pubkey;

    use super::*;
    use crate::rpc::{
        compile_message, ComputeBudgetConfig, Context, GetShieldedTransactionsBySignatureResponse,
        IndexedShieldedTransaction, ShieldedTransaction,
    };

    /// What one status lookup answers.
    #[derive(Clone)]
    enum Lookup {
        Fails,
        Missing,
        Processed,
        Confirmed(Option<ChainError>),
    }

    /// What the indexer answers a lookup by signature.
    #[derive(Clone, Copy)]
    enum Indexer {
        Has,
        Lacks,
        Behind,
    }

    /// An RPC whose status lookups answer `lookups` in turn, the last one from
    /// then on, at `block_height`, and whose indexer answers `indexer`.
    /// Counts the lookups of each.
    struct Lookups {
        lookups: Mutex<VecDeque<Lookup>>,
        block_height: u64,
        asked: Mutex<u32>,
        indexer: Indexer,
        indexer_asked: Mutex<u32>,
    }

    impl Lookups {
        fn new(lookups: &[Lookup], block_height: u64) -> Self {
            Self {
                lookups: Mutex::new(lookups.iter().cloned().collect()),
                block_height,
                asked: Mutex::new(0),
                indexer: Indexer::Lacks,
                indexer_asked: Mutex::new(0),
            }
        }

        fn with_indexer(self, indexer: Indexer) -> Self {
            Self { indexer, ..self }
        }
    }

    #[async_trait]
    impl AsyncRpc for Lookups {
        async fn get_block_height(&self) -> Result<u64, ClientError> {
            Ok(self.block_height)
        }

        async fn get_slot(&self) -> Result<u64, ClientError> {
            Ok(100)
        }

        async fn get_signature_statuses(
            &self,
            signatures: Vec<Signature>,
        ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
            *self.asked.lock().unwrap() += 1;
            let lookup = {
                let mut lookups = self.lookups.lock().unwrap();
                if lookups.len() > 1 {
                    lookups.pop_front()
                } else {
                    lookups.front().cloned()
                }
            };
            let level = |err, confirmation_status| {
                Some(TransactionStatus {
                    slot: 1,
                    confirmations: Some(1),
                    status: Ok(()),
                    err,
                    confirmation_status: Some(confirmation_status),
                })
            };
            let status = match lookup.expect("a scripted lookup") {
                Lookup::Fails => return Err(ClientError::Rpc("lookup timed out".into())),
                Lookup::Missing => None,
                Lookup::Processed => level(None, TransactionConfirmationStatus::Processed),
                Lookup::Confirmed(err) => level(err, TransactionConfirmationStatus::Confirmed),
            };
            Ok(signatures.iter().map(|_| status.clone()).collect())
        }

        async fn get_shielded_transactions_by_signature(
            &self,
            signature: Signature,
            _: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
            *self.indexer_asked.lock().unwrap() += 1;
            let transactions = match self.indexer {
                Indexer::Behind => {
                    return Err(ClientError::IndexerNotCaughtUp {
                        required: 100,
                        indexed: 90,
                        attempts: 8,
                    })
                }
                Indexer::Lacks => Vec::new(),
                Indexer::Has => vec![IndexedShieldedTransaction {
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
                }],
            };
            Ok(GetShieldedTransactionsBySignatureResponse {
                context: Context {
                    block_time: 0,
                    slot: 100,
                },
                output_tree_id: None,
                transactions,
            })
        }
    }

    const QUICK: IndexerPollConfig = IndexerPollConfig {
        num_retries: 2,
        delay_ms: 1,
        max_delay_ms: 1,
    };

    async fn reconciled(rpc: &Lookups, indexed: bool) -> Result<(), ClientError> {
        reconcile(rpc, Signature::from([3; 64]), Some(100), indexed, QUICK).await
    }

    /// The lookups last until the blockhash expires, however short the
    /// retry schedule, and only a confirmed status counts: a processed one
    /// can still be dropped with its fork.
    #[tokio::test(start_paused = true)]
    async fn a_lost_send_is_looked_up_until_it_is_confirmed() {
        let unseen = Lookups::new(
            &[
                Lookup::Missing,
                Lookup::Missing,
                Lookup::Missing,
                Lookup::Missing,
                Lookup::Confirmed(None),
            ],
            99,
        );
        assert!(reconciled(&unseen, true).await.is_ok());
        assert_eq!(*unseen.indexer_asked.lock().unwrap(), 0);

        let processed = Lookups::new(&[Lookup::Processed, Lookup::Confirmed(None)], 99);
        assert!(reconciled(&processed, true).await.is_ok());
        assert_eq!(*processed.asked.lock().unwrap(), 2);

        let flaky = Lookups::new(&[Lookup::Fails, Lookup::Confirmed(None)], 99);
        assert!(reconciled(&flaky, true).await.is_ok());
    }

    /// Each outcome says whether sending again is safe.
    #[tokio::test(start_paused = true)]
    async fn a_lost_send_ends_refused_expired_or_unknown() {
        let refused = Lookups::new(
            &[Lookup::Confirmed(Some(ChainError::InsufficientFundsForFee))],
            99,
        );
        assert!(matches!(
            reconciled(&refused, true).await,
            Err(ClientError::SolanaRpcTransaction { source, .. })
                if source.get_transaction_error() == Some(ChainError::InsufficientFundsForFee)
        ));

        let expired = Lookups::new(&[Lookup::Missing], 101);
        assert!(matches!(
            reconciled(&expired, false).await,
            Err(ClientError::TransactionExpired { .. })
        ));

        let unreachable = Lookups::new(&[Lookup::Fails], 99);
        assert!(matches!(
            reconciled(&unreachable, true).await,
            Err(ClientError::TransactionOutcomeUnknown { message, .. })
                if message.contains("lookup timed out")
        ));

        let unconfirmed = Lookups::new(&[Lookup::Processed], 99);
        assert!(matches!(
            reconciled(&unconfirmed, true).await,
            Err(ClientError::TransactionOutcomeUnknown { .. })
        ));

        // Without its last valid block height, a transaction never seen
        // cannot be told expired, so it ends unknown rather than waiting
        // forever.
        let unseen = Lookups::new(&[Lookup::Missing], 1_000);
        assert!(matches!(
            reconcile(&unseen, Signature::from([3; 64]), None, true, QUICK).await,
            Err(ClientError::TransactionOutcomeUnknown { message, .. })
                if message.contains("last valid block height")
        ));
        assert_eq!(*unseen.asked.lock().unwrap(), QUICK.num_retries + 1);
    }

    /// Past its blockhash and out of the status cache, as a transaction looked
    /// up long after it landed is, a shielded-pool transaction is expired only
    /// when the indexer lacks it, and unknown while the indexer cannot say.
    #[tokio::test(start_paused = true)]
    async fn an_old_transaction_is_looked_for_at_the_indexer() {
        let gone = || Lookups::new(&[Lookup::Missing], 101);

        let indexed = gone().with_indexer(Indexer::Has);
        assert!(reconciled(&indexed, true).await.is_ok());

        let expired = gone();
        assert!(matches!(
            reconciled(&expired, true).await,
            Err(ClientError::TransactionExpired { .. })
        ));
        assert_eq!(*expired.indexer_asked.lock().unwrap(), 1);

        let behind = gone().with_indexer(Indexer::Behind);
        assert!(matches!(
            reconciled(&behind, true).await,
            Err(ClientError::TransactionOutcomeUnknown { .. })
        ));
        assert_eq!(*behind.indexer_asked.lock().unwrap(), QUICK.num_retries + 1);

        // The indexer does not record a user registry transaction.
        let registry = gone().with_indexer(Indexer::Behind);
        assert!(matches!(
            reconciled(&registry, false).await,
            Err(ClientError::TransactionExpired { .. })
        ));
        assert_eq!(*registry.indexer_asked.lock().unwrap(), 0);
    }

    /// A send refused in simulation was never sent and settles at once; one
    /// found already processed may have landed and is looked up.
    #[test]
    fn only_an_already_processed_simulation_settles_nothing() {
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
        assert!(settles_the_send(&preflight("InsufficientFundsForFee")));
        assert!(!settles_the_send(&preflight("AlreadyProcessed")));
        assert!(!settles_the_send(&ClientError::Rpc(
            "connection reset".into()
        )));
    }

    #[test]
    fn only_a_shielded_pool_call_is_indexed() {
        let payer = Pubkey::new_unique();
        let message = |program_id| {
            compile_message(
                &payer,
                &[Instruction::new_with_bytes(program_id, &[0], Vec::new())],
                Hash::default(),
                ComputeBudgetConfig::new(200_000),
            )
            .unwrap()
        };
        assert!(calls_shielded_pool(&message(PROGRAM_ID_PUBKEY)));
        assert!(!calls_shielded_pool(&message(Pubkey::new_unique())));
    }
}
