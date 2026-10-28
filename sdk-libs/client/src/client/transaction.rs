use std::{future::Future, sync::Arc, time::Duration};

use solana_address::Address;
use solana_hash::Hash;
use solana_keypair::Signer;
use solana_message::VersionedMessage;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use spr_instruction::instruction::{Transact, TransactInterfaceTransferAccounts};
use spr_interface::{
    instruction::{instruction_data::transact::TransactProof, TransactIxData},
    pda,
};
use spr_keypair::SigningKey;
use spr_transaction::instructions::transact::SppProofInputs;
use tokio::time::Instant;

use crate::{
    authority::ProofAuthority,
    error::ClientError,
    prover::{
        transact::witness::{assemble, assemble_confidential_eddsa, AssembledTransfer},
        verify_confidential_transfer_proof, ProofCompressed, Prover, TransferProofResult,
    },
    rpc::{
        compile_message, sign_transaction, AsyncRpc, ComputeBudgetConfig, IndexerRpcConfig,
        SettlementAccountValidation,
    },
};

use super::{
    prove_on_blocking_pool, validation::validate_fee_payer_pubkey, AsyncIndexer, AsyncZolanaClient,
    BlockingIndexer, BlockingRpc, TransferPreparation, ZolanaClient,
};
use crate::prover::indexed::{IndexedTransferPreparation, IndexedTransferRail};

/// A signed shielded transaction ready for proof assembly and submission.
///
/// Produced by signing a `ConfidentialTransaction`; consumed by
/// [`ZolanaClient`]'s submission helpers.
pub struct SignedPrivateTransaction {
    pub transaction: SppProofInputs,
    pub settlement_transfers: Vec<TransactInterfaceTransferAccounts>,
}

impl<R: AsyncRpc, I: AsyncIndexer> AsyncZolanaClient<R, I> {
    /// Ask the configured prover for a default-ring EdDSA transfer proof and
    /// verify it locally before returning its transaction wire encoding.
    pub async fn prove_confidential_transfer_result(
        &self,
        result: &TransferProofResult,
    ) -> Result<ProofCompressed, ClientError> {
        let proof = self.prove_transfer(&result.inputs).await?;
        verify_confidential_transfer_proof(result, &proof)?;
        ProofCompressed::try_from(proof)
    }

    /// Fetch the input merkle proofs from the indexer and prove the transaction
    /// with the client's prover, returning the assembled `transact` instruction
    /// data ready for the [`Transact`] builder.
    ///
    /// `authority` completes the witness: the assembled inputs carry no
    /// nullifier secret, and it fills in the ones its owner holds.
    pub async fn prove_transact(
        &self,
        proof_inputs: SppProofInputs,
        config: Option<IndexerRpcConfig>,
        authority: &dyn ProofAuthority,
    ) -> Result<TransactIxData, ClientError> {
        if let Some(server) = self.indexed_prover() {
            return Ok(server
                .prove_indexed(
                    &TransferPreparation {
                        transaction: proof_inputs,
                        config: config.unwrap_or(self.indexer_config),
                    }
                    .prepare(authority)?,
                )
                .await?
                .data);
        }
        let witnesses = self
            .indexer
            .transaction_proofs(&proof_inputs.input_utxos, config)
            .await?;
        let mut assembled = assemble(
            proof_inputs,
            &witnesses.spend_proofs,
            &witnesses.dummy_nullifier_proofs,
        )?;
        let proof = self.prove_assembled(&mut assembled, authority).await?;
        Ok(assembled.with_proof(proof))
    }

    /// [`Self::prove_transact`] on the `ConfidentialEddsa` rail: `owner` signs
    /// the transaction message digest inside the proof instead of signing the
    /// transaction, so another account can pay for it. `authority` still
    /// completes the owner's inputs.
    pub async fn prove_transact_confidential_eddsa(
        &self,
        proof_inputs: SppProofInputs,
        config: Option<IndexerRpcConfig>,
        authority: &dyn ProofAuthority,
        owner: &SigningKey,
    ) -> Result<TransactIxData, ClientError> {
        if let Some(server) = self.indexed_prover() {
            let prepared = IndexedTransferPreparation {
                transaction: proof_inputs,
                rail: IndexedTransferRail::ConfidentialEddsa { owner },
            }
            .prepare(authority)?;
            let prepared = match config.unwrap_or(self.indexer_config).require_slot {
                Some(slot) => prepared.with_min_context_slot(slot),
                None => prepared,
            };
            return Ok(server.prove_indexed(&prepared).await?.data);
        }
        let witnesses = self
            .indexer
            .transaction_proofs(&proof_inputs.input_utxos, config)
            .await?;
        let mut assembled = assemble_confidential_eddsa(
            proof_inputs,
            &witnesses.spend_proofs,
            &witnesses.dummy_nullifier_proofs,
            owner,
        )?;
        let proof = self.prove_assembled(&mut assembled, authority).await?;
        Ok(assembled.with_proof(proof))
    }

    /// Complete the inputs, prove them and verify the proof; one call rather
    /// than "complete, then prove", since nothing between assembly and the
    /// prover has any use for a witness carrying key material.
    async fn prove_assembled(
        &self,
        assembled: &mut AssembledTransfer,
        authority: &dyn ProofAuthority,
    ) -> Result<TransactProof, ClientError> {
        authority.complete_inputs(&mut assembled.prover_inputs.inputs)?;
        let proof = {
            let _t = crate::prover::timing::Phase::start("prove_transfer", 0);
            self.prove_request(assembled.request()?).await?
        };
        assembled.accept_proof(proof)
    }
}

impl<R: BlockingRpc, I: BlockingIndexer> ZolanaClient<R, I> {
    /// See [`AsyncZolanaClient::prove_transact`].
    pub fn prove_transact(
        &self,
        proof_inputs: SppProofInputs,
        config: Option<IndexerRpcConfig>,
        authority: &dyn ProofAuthority,
    ) -> Result<TransactIxData, ClientError> {
        self.block_on(self.client.prove_transact(proof_inputs, config, authority))
    }

    /// See [`AsyncZolanaClient::prove_transact_confidential_eddsa`].
    pub fn prove_transact_confidential_eddsa(
        &self,
        proof_inputs: SppProofInputs,
        config: Option<IndexerRpcConfig>,
        authority: &dyn ProofAuthority,
        owner: &SigningKey,
    ) -> Result<TransactIxData, ClientError> {
        self.block_on(self.client.prove_transact_confidential_eddsa(
            proof_inputs,
            config,
            authority,
            owner,
        ))
    }
}

/// A message awaiting its signatures, and the last block height at which its
/// blockhash lets it land.
#[derive(Clone, Debug, PartialEq)]
pub struct UnsignedMessage {
    pub message: VersionedMessage,
    pub last_valid_block_height: u64,
}

/// A signed private transaction on its way to the chain: who pays, who
/// completes the proof inputs, and what proves it. [`Self::finish_unsigned`]
/// builds the message its signers sign, for signers outside this client;
/// [`Self::send`] signs, sends and confirms it.
pub struct Submission<'a> {
    pub signed: &'a SignedPrivateTransaction,
    pub fee_payer: Address,
    /// Completes the proof inputs: the assembled inputs carry no nullifier
    /// secret, and it fills in the ones its owner holds.
    pub authority: &'a dyn ProofAuthority,
    /// Proves this submission in place of the client's prover, for a caller
    /// that chooses where each transaction is proved. As with
    /// [`AsyncZolanaClient::with_prover`], the client then fetches the proof
    /// data itself, so the submission never takes the prover server's indexed
    /// route.
    pub prover: Option<Arc<dyn Prover>>,
    /// The owner that authorizes inside the proof instead of signing the transaction.
    pub confidential_eddsa_owner: Option<&'a SigningKey>,
}

impl<'a> Submission<'a> {
    pub fn new(
        signed: &'a SignedPrivateTransaction,
        fee_payer: Address,
        authority: &'a dyn ProofAuthority,
    ) -> Self {
        Self {
            signed,
            fee_payer,
            authority,
            prover: None,
            confidential_eddsa_owner: None,
        }
    }

    #[must_use]
    pub fn with_prover(mut self, prover: Arc<dyn Prover>) -> Self {
        self.prover = Some(prover);
        self
    }

    /// Authorize this owner inside the proof and omit its owner-signer account.
    /// Prepare the transaction with `with_transaction_signers` so it selects a
    /// shape supported by this rail. Every other owner still signs normally.
    #[must_use]
    pub fn with_confidential_eddsa_owner(mut self, owner: &'a SigningKey) -> Self {
        self.confidential_eddsa_owner = Some(owner);
        self
    }

    /// The unsigned v1 message of this submission, proved through `client`,
    /// and the last block height it can land at.
    ///
    /// Fetches the blockhash beside the proof and retries after proving if
    /// that request is still pending, failed, or began more than ten seconds
    /// ago, including RPC latency. Proof errors return without waiting for
    /// the blockhash request.
    /// Callers used to fetch one and hand it in,
    /// which put a multi-second proof between the blockhash and the send.
    /// Under load that window exceeded the blockhash lifetime and the
    /// transaction was rejected at submission, having already paid for the
    /// sync and the proof: an 80-worker run lost 297 of 337 transfers to
    /// "Blockhash not found".
    pub async fn finish_unsigned<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<UnsignedMessage, ClientError> {
        let mut owner_signers = submission_owner_signers(self.signed, self.fee_payer)?;
        if let Some(owner) = self.confidential_eddsa_owner {
            let owner = Address::new_from_array(owner.pubkey().as_ed25519()?);
            owner_signers.retain(|signer| *signer != owner);
        }
        let proving = async {
            Ok::<_, ClientError>(match (&self.prover, client.indexed_prover()) {
                (None, Some(server)) => {
                    let prepared = match self.confidential_eddsa_owner {
                        Some(owner) => {
                            let prepared = IndexedTransferPreparation {
                                transaction: self.signed.transaction.clone(),
                                rail: IndexedTransferRail::ConfidentialEddsa { owner },
                            }
                            .prepare(self.authority)?;
                            match client.indexer_config.require_slot {
                                Some(slot) => prepared.with_min_context_slot(slot),
                                None => prepared,
                            }
                        }
                        None => client
                            .transfer_preparation(self.signed)
                            .prepare(self.authority)?,
                    };
                    let proved = server.prove_indexed(&prepared).await?;
                    (
                        indexed_trees(proved.input_tree_ids, &self.signed.transaction),
                        proved.data,
                    )
                }
                (prover, _) => {
                    let witnesses = client
                        .indexer
                        .transaction_proofs(&self.signed.transaction.input_utxos, None)
                        .await?;
                    let mut assembled = match self.confidential_eddsa_owner {
                        Some(owner) => assemble_confidential_eddsa(
                            self.signed.transaction.clone(),
                            &witnesses.spend_proofs,
                            &witnesses.dummy_nullifier_proofs,
                            owner,
                        )?,
                        None => assemble(
                            self.signed.transaction.clone(),
                            &witnesses.spend_proofs,
                            &witnesses.dummy_nullifier_proofs,
                        )?,
                    };
                    let proof = match prover {
                        Some(prover) => {
                            self.authority
                                .complete_inputs(&mut assembled.prover_inputs.inputs)?;
                            let proof =
                                prove_on_blocking_pool(Arc::clone(prover), assembled.request()?)
                                    .await?;
                            assembled.accept_proof(proof)?
                        }
                        None => {
                            client
                                .prove_assembled(&mut assembled, self.authority)
                                .await?
                        }
                    };
                    (
                        transact_trees(&assembled, &self.signed.transaction),
                        assembled.with_proof(proof),
                    )
                }
            })
        };
        let ((trees, data), (recent_blockhash, last_valid_block_height)) =
            prove_with_blockhash(client.rpc(), proving).await?;
        Ok(UnsignedMessage {
            message: build_unsigned_message(
                client.compute_budget(),
                self.fee_payer,
                trees,
                owner_signers,
                self.signed.settlement_transfers.clone(),
                data,
                recent_blockhash,
            )?,
            last_valid_block_height,
        })
    }

    /// Prove, sign with `signers`, send through `client` and wait until the
    /// transaction is confirmed and indexed. `signers` are the fee payer and
    /// the native owners the transaction's inputs name, except the owner whose
    /// key was supplied with [`Self::with_confidential_eddsa_owner`]. One keypair
    /// playing both roles signs once.
    pub async fn send<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
        signers: &[&dyn Signer],
    ) -> Result<Signature, ClientError> {
        let unsigned = self.finish_unsigned(client).await?;
        let transaction = sign_transaction(unsigned.message, signers)?;
        let signature = client.process_transaction(transaction).await?;
        client.confirm_private_transaction(signature).await?;
        Ok(signature)
    }

    /// See [`Self::finish_unsigned`].
    pub fn finish_unsigned_sync<R: BlockingRpc, I: BlockingIndexer>(
        &self,
        client: &ZolanaClient<R, I>,
    ) -> Result<UnsignedMessage, ClientError> {
        client.block_on(self.finish_unsigned(&client.client))
    }

    /// See [`Self::send`].
    pub fn send_sync<R: BlockingRpc, I: BlockingIndexer>(
        &self,
        client: &ZolanaClient<R, I>,
        signers: &[&dyn Signer],
    ) -> Result<Signature, ClientError> {
        client.block_on(self.send(&client.client, signers))
    }
}

/// Conservative reuse window for a blockhash prefetched while proving,
/// measured from the RPC request's start. This is a client refresh policy;
/// expiration follows chain state and the returned `last_valid_block_height`.
const MAX_PREFETCHED_BLOCKHASH_AGE: Duration = Duration::from_secs(10);

/// Prove and fetch the latest blockhash concurrently. Reuse the blockhash
/// only if its request began at most [`MAX_PREFETCHED_BLOCKHASH_AGE`] ago;
/// otherwise retry after proving. If proving finishes first, drop the pending
/// prefetch before retrying. Proof errors return without waiting for the fetch,
/// while a failed fetch is retried only after a successful proof.
pub(super) async fn prove_with_blockhash<R: AsyncRpc, T>(
    rpc: &R,
    proving: impl Future<Output = Result<T, ClientError>>,
) -> Result<(T, (Hash, u64)), ClientError> {
    let requested_at = Instant::now();
    let (proved, prefetched) = {
        let prefetch = rpc.get_latest_blockhash();
        tokio::pin!(proving, prefetch);
        tokio::select! {
            // Prefer a ready prefetch when both futures are ready.
            biased;
            blockhash = &mut prefetch => (proving.await?, Some(blockhash)),
            proved = &mut proving => (proved?, None),
        }
    };
    let blockhash = match prefetched {
        Some(Ok(blockhash)) if requested_at.elapsed() <= MAX_PREFETCHED_BLOCKHASH_AGE => blockhash,
        _ => rpc.get_latest_blockhash().await?,
    };
    Ok((proved, blockhash))
}

/// The owners who sign `signed`, once it is known that `fee_payer` is the
/// payer its proof binds and that it writes no cache, which these submission
/// paths cannot do.
fn submission_owner_signers(
    signed: &SignedPrivateTransaction,
    fee_payer: Address,
) -> Result<Vec<Address>, ClientError> {
    validate_fee_payer_pubkey(&signed.transaction.payer, fee_payer)?;
    if signed.transaction.cache_accounts.write.is_some() {
        return Err(ClientError::CacheWriteNeedsWriter);
    }
    Ok(signed.transaction.owner_signer_pubkeys()?)
}

/// The trees a `Transact` names, as the raw ids everything upstream carries.
/// The accounts are derived here, at the one point the instruction needs them.
struct TransactTrees {
    /// The trees the inputs are nullified in, one per `tree_contexts` entry and
    /// in that order, which is the order the builder pairs them up in.
    input_tree_ids: Vec<u16>,
    output_tree_id: u16,
    read_cache: Option<Pubkey>,
}

/// The trees of a transfer the prover server proved on its indexed route,
/// which reports the input trees it resolved.
fn indexed_trees(input_tree_ids: Vec<u16>, transaction: &SppProofInputs) -> TransactTrees {
    TransactTrees {
        input_tree_ids,
        output_tree_id: transaction.output_tree_id,
        read_cache: transaction.cache_accounts.read,
    }
}

/// Read both from the transaction itself: assembly declared the input trees in
/// the order it emitted their contexts, and the output tree is the id every
/// output commitment was hashed under. Nothing the client holds on the side can
/// disagree with either.
fn transact_trees(assembled: &AssembledTransfer, transaction: &SppProofInputs) -> TransactTrees {
    TransactTrees {
        input_tree_ids: assembled.input_tree_ids.clone(),
        output_tree_id: transaction.output_tree_id,
        read_cache: assembled.cache_accounts.read,
    }
}

fn build_unsigned_message(
    compute_budget: ComputeBudgetConfig,
    fee_payer: Pubkey,
    trees: TransactTrees,
    owner_signers: Vec<Pubkey>,
    settlement_transfers: Vec<TransactInterfaceTransferAccounts>,
    transact_data: spr_interface::instruction::instruction_data::transact::TransactIxData,
    recent_blockhash: Hash,
) -> Result<VersionedMessage, ClientError> {
    SettlementAccountValidation {
        transfers: &transact_data.interface_transfers,
        accounts: &settlement_transfers,
    }
    .validate()?;
    let transact = Transact {
        payer: fee_payer,
        input_trees: trees
            .input_tree_ids
            .iter()
            .copied()
            .map(pda::tree)
            .collect(),
        output_tree: pda::tree(trees.output_tree_id),
        owner_signers,
        interface_transfer_accounts: settlement_transfers,
        data: transact_data,
    };
    let transact_ix = match trees.read_cache {
        Some(cache) => transact.instruction_with_cache_read(cache),
        None => transact.instruction(),
    };
    // The transact is the only instruction: a v1 message states its compute
    // ceiling and its priority fee in the header, so nothing rides along to
    // set them.
    compile_message(
        &fee_payer,
        core::slice::from_ref(&transact_ix),
        recent_blockhash,
        compute_budget,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    use super::*;

    /// Each fetch returns its count as the hash and height. The first fetch
    /// can fail, arrive late, or never finish; retries can also be delayed.
    struct Blockhashes {
        fetched: AtomicU32,
        first_dropped: AtomicBool,
        first: FirstFetch,
        retry_delay: Duration,
    }

    enum FirstFetch {
        Ready,
        Failed,
        Delayed(Duration),
        Pending,
    }

    impl Blockhashes {
        fn new(first: FirstFetch) -> Self {
            Self {
                fetched: AtomicU32::new(0),
                first_dropped: AtomicBool::new(false),
                first,
                retry_delay: Duration::ZERO,
            }
        }

        fn fetched(&self) -> u32 {
            self.fetched.load(Ordering::SeqCst)
        }
    }

    struct FetchDropped<'a>(&'a AtomicBool);

    impl Drop for FetchDropped<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl AsyncRpc for Blockhashes {
        async fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
            let count = self.fetched.fetch_add(1, Ordering::SeqCst) + 1;
            if count == 1 {
                let _dropped = FetchDropped(&self.first_dropped);
                match self.first {
                    FirstFetch::Ready => {}
                    FirstFetch::Failed => return Err(ClientError::Rpc("blockhash".into())),
                    FirstFetch::Delayed(delay) => tokio::time::sleep(delay).await,
                    FirstFetch::Pending => std::future::pending::<()>().await,
                }
            } else {
                assert!(
                    self.first_dropped.load(Ordering::SeqCst),
                    "drop the prefetch before starting its replacement"
                );
                if !self.retry_delay.is_zero() {
                    tokio::time::sleep(self.retry_delay).await;
                }
            }
            Ok((Hash::new_from_array([count as u8; 32]), count.into()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_short_proof_uses_the_blockhash_fetched_beside_it() {
        let rpc = Blockhashes::new(FirstFetch::Delayed(Duration::from_secs(2)));
        let started = Instant::now();
        let proving = async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(7)
        };
        let (proved, (hash, height)) = prove_with_blockhash(&rpc, proving).await.unwrap();
        assert_eq!(
            (proved, hash, height),
            (7, Hash::new_from_array([1; 32]), 1)
        );
        assert_eq!(rpc.fetched(), 1);
        assert_eq!(started.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn a_long_proof_fetches_the_blockhash_again() {
        let rpc = Blockhashes::new(FirstFetch::Ready);
        let proving = async {
            tokio::time::sleep(MAX_PREFETCHED_BLOCKHASH_AGE + Duration::from_secs(1)).await;
            Ok(7)
        };
        let (_, (_, height)) = prove_with_blockhash(&rpc, proving).await.unwrap();
        assert_eq!((height, rpc.fetched()), (2, 2));
    }

    #[tokio::test(start_paused = true)]
    async fn a_fetch_that_failed_beside_the_proof_is_made_again_after_it() {
        let rpc = Blockhashes::new(FirstFetch::Failed);
        let proving = async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            assert_eq!(rpc.fetched(), 1, "retry only after proving succeeds");
            Ok(7)
        };
        let (_, (_, height)) = prove_with_blockhash(&rpc, proving).await.unwrap();
        assert_eq!((height, rpc.fetched()), (2, 2));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_proof_fails_without_another_fetch() {
        let rpc = Blockhashes::new(FirstFetch::Failed);
        let failed = prove_with_blockhash::<_, u32>(&rpc, async {
            tokio::task::yield_now().await;
            Err(ClientError::Rpc("proof".into()))
        })
        .await;
        assert!(matches!(failed, Err(ClientError::Rpc(message)) if message == "proof"));
        assert_eq!(rpc.fetched(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn rpc_latency_counts_toward_the_blockhash_age() {
        // The response is slow whether proving finishes before or after it.
        // In both cases the request started too long ago to reuse its hash.
        for proof_seconds in [5, 30] {
            let rpc = Blockhashes::new(FirstFetch::Delayed(Duration::from_secs(25)));
            let proving = async {
                tokio::time::sleep(Duration::from_secs(proof_seconds)).await;
                Ok(7)
            };
            let (proved, (hash, height)) = prove_with_blockhash(&rpc, proving).await.unwrap();
            assert_eq!(
                (proved, hash, height, rpc.fetched()),
                (7, Hash::new_from_array([2; 32]), 2, 2)
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_successful_proof_cancels_a_pending_prefetch_before_retrying() {
        for proof_seconds in [5, 30] {
            let rpc = Blockhashes::new(FirstFetch::Pending);
            let started = Instant::now();
            let proving = async {
                tokio::time::sleep(Duration::from_secs(proof_seconds)).await;
                Ok(7)
            };
            let result = tokio::time::timeout(
                Duration::from_secs(proof_seconds + 1),
                prove_with_blockhash(&rpc, proving),
            )
            .await
            .expect("a successful proof must not wait for a pending prefetch")
            .unwrap();
            assert_eq!(result, (7, (Hash::new_from_array([2; 32]), 2)));
            assert_eq!(rpc.fetched(), 2);
            assert_eq!(started.elapsed(), Duration::from_secs(proof_seconds));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_prefetch_does_not_add_latency_after_proving() {
        let mut rpc = Blockhashes::new(FirstFetch::Delayed(Duration::from_secs(25)));
        rpc.retry_delay = Duration::from_secs(25);
        let started = Instant::now();
        let proving = async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(7)
        };
        let result = prove_with_blockhash(&rpc, proving).await.unwrap();
        assert_eq!(result, (7, (Hash::new_from_array([2; 32]), 2)));
        assert_eq!(rpc.fetched(), 2);
        assert_eq!(started.elapsed(), Duration::from_secs(30));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_proof_does_not_wait_for_a_pending_blockhash() {
        let rpc = Blockhashes::new(FirstFetch::Pending);
        let proving = async {
            tokio::task::yield_now().await;
            Err::<u32, _>(ClientError::Rpc("proof".into()))
        };
        let failed =
            tokio::time::timeout(Duration::from_secs(1), prove_with_blockhash(&rpc, proving))
                .await
                .expect("a proof error must not wait for the pending blockhash request");
        assert!(matches!(failed, Err(ClientError::Rpc(message)) if message == "proof"));
        assert_eq!(rpc.fetched(), 1);
    }
}
