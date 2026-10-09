use std::sync::Arc;

use solana_address::Address;
use solana_hash::Hash;
use solana_keypair::Signer;
use solana_message::VersionedMessage;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_interface::{
    instruction::{instruction_data::transact::TransactProof, TransactIxData},
    pda,
};
use zolana_program::instruction::{Transact, TransactInterfaceTransferAccounts};
use zolana_transaction::instructions::transact::SppProofInputs;

use crate::{
    authority::ProofAuthority,
    error::ClientError,
    prover::{
        transact::witness::{assemble, AssembledTransfer},
        verify_confidential_transfer_inputs, verify_confidential_transfer_proof, ProofCompressed,
        Prover, TransferProofResult,
    },
    rpc::{
        compile_message, sign_transaction, AsyncRpc, ComputeBudgetConfig, IndexerRpcConfig, Rpc,
        SettlementAccountValidation,
    },
};

use super::{
    prove_on_blocking_pool, validation::validate_fee_payer_pubkey, AsyncIndexer, AsyncZolanaClient,
    BlockingIndexer, TransferPreparation, ZolanaClient,
};

/// A signed shielded transaction ready for proof assembly and submission.
///
/// Produced by signing a `ConfidentialTransaction`; consumed by
/// [`ZolanaClient`]'s submission helpers.
pub struct SignedPrivateTransaction {
    pub transaction: SppProofInputs,
    pub settlement_transfers: Vec<TransactInterfaceTransferAccounts>,
}

impl<R: AsyncRpc, I: AsyncIndexer> AsyncZolanaClient<R, I> {
    /// Ask the configured prover for a default-ring Ed25519 transfer proof and
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
        let commitments = proof_inputs.input_utxo_hashes()?;
        let witnesses = self
            .indexer
            .input_witnesses(&commitments, &proof_inputs.dummy_nullifiers(), config)
            .await?;
        let mut assembled = assemble(
            proof_inputs,
            &witnesses.spend_proofs,
            &witnesses.dummy_nullifier_proofs,
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
        let inputs = &mut assembled.prover_inputs;
        authority.complete_inputs(&mut inputs.inputs)?;
        let proof = {
            let _t = crate::prover::timing::Phase::start("prove_transfer", 0);
            self.prove_transfer(inputs).await?
        };
        verify_confidential_transfer_inputs(inputs, assembled.public_input_hash, &proof)?;
        Ok(ProofCompressed::try_from(proof)?.to_transact_proof())
    }
}

impl<R: Rpc + Send + Sync + 'static, I: BlockingIndexer> ZolanaClient<R, I> {
    /// See [`AsyncZolanaClient::prove_transact`].
    pub fn prove_transact(
        &self,
        proof_inputs: SppProofInputs,
        config: Option<IndexerRpcConfig>,
        authority: &dyn ProofAuthority,
    ) -> Result<TransactIxData, ClientError> {
        self.block_on(self.client.prove_transact(proof_inputs, config, authority))
    }
}

/// A signed private transaction on its way to the chain: who pays, who
/// completes the proof inputs, and what proves it. [`Self::finish_unsigned`]
/// builds the message the fee payer signs; [`Self::send`] signs, sends and
/// confirms it.
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
        }
    }

    #[must_use]
    pub fn with_prover(mut self, prover: Arc<dyn Prover>) -> Self {
        self.prover = Some(prover);
        self
    }

    /// The unsigned v1 message of this submission, proved through `client`.
    ///
    /// Fetches the blockhash itself, after proving rather than before.
    /// Callers used to fetch one and hand it in, which put a multi-second
    /// proof between the blockhash and the send. Under load that window
    /// exceeded the blockhash lifetime and the transaction was rejected at
    /// submission, having already paid for the sync and the proof: an
    /// 80-worker run lost 297 of 337 transfers to "Blockhash not found".
    pub async fn finish_unsigned<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<VersionedMessage, ClientError> {
        let owner_signers = submission_owner_signers(self.signed, self.fee_payer)?;
        let (trees, data) = match (&self.prover, client.indexed_prover()) {
            (None, Some(server)) => {
                let proved = server
                    .prove_indexed(
                        &client
                            .transfer_preparation(self.signed)
                            .prepare(self.authority)?,
                    )
                    .await?;
                (
                    indexed_trees(proved.input_tree_ids, &self.signed.transaction),
                    proved.data,
                )
            }
            (prover, _) => {
                let commitments = self.signed.transaction.input_utxo_hashes()?;
                let witnesses = client
                    .indexer
                    .input_witnesses(
                        &commitments,
                        &self.signed.transaction.dummy_nullifiers(),
                        None,
                    )
                    .await?;
                let mut assembled = assemble(
                    self.signed.transaction.clone(),
                    &witnesses.spend_proofs,
                    &witnesses.dummy_nullifier_proofs,
                )?;
                let proof = match prover {
                    Some(prover) => {
                        let inputs = &mut assembled.prover_inputs;
                        self.authority.complete_inputs(&mut inputs.inputs)?;
                        let proof = prove_on_blocking_pool(Arc::clone(prover), inputs).await?;
                        verify_confidential_transfer_inputs(
                            inputs,
                            assembled.public_input_hash,
                            &proof,
                        )?;
                        ProofCompressed::try_from(proof)?.to_transact_proof()
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
        };
        // Last thing before building, so the blockhash is as young as it can be
        // when the transaction reaches the cluster.
        let (recent_blockhash, _) = client.rpc().get_latest_blockhash().await?;
        build_unsigned_message(
            client.compute_budget(),
            self.fee_payer,
            trees,
            owner_signers,
            self.signed.settlement_transfers.clone(),
            data,
            recent_blockhash,
        )
    }

    /// Prove, sign with `signers`, send through `client` and wait until the
    /// transaction is confirmed and indexed. `signers` are the fee payer and
    /// the native owners the transaction's inputs name; one keypair playing
    /// both roles signs once.
    pub async fn send<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
        signers: &[&dyn Signer],
    ) -> Result<Signature, ClientError> {
        let message = self.finish_unsigned(client).await?;
        let transaction = sign_transaction(message, signers)?;
        let signature = client.process_transaction(transaction).await?;
        client.confirm_private_transaction(signature).await?;
        Ok(signature)
    }

    /// See [`Self::finish_unsigned`].
    pub fn finish_unsigned_sync<R: Rpc + Send + Sync + 'static, I: BlockingIndexer>(
        &self,
        client: &ZolanaClient<R, I>,
    ) -> Result<VersionedMessage, ClientError> {
        client.block_on(self.finish_unsigned(&client.client))
    }

    /// See [`Self::send`].
    pub fn send_sync<R: Rpc + Send + Sync + 'static, I: BlockingIndexer>(
        &self,
        client: &ZolanaClient<R, I>,
        signers: &[&dyn Signer],
    ) -> Result<Signature, ClientError> {
        client.block_on(self.send(&client.client, signers))
    }
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
    transact_data: zolana_interface::instruction::instruction_data::transact::TransactIxData,
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
