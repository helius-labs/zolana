use solana_hash::Hash;
use solana_message::VersionedMessage;
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{Transact, TransactInterfaceTransferAccounts, TransactIxData},
    pda,
};
use zolana_transaction::instructions::transact::SppProofInputs;

use crate::{
    authority::ProofAuthority,
    error::ClientError,
    prover::{
        transact::witness::{assemble, AssembledTransfer},
        verify_confidential_transfer_inputs, verify_confidential_transfer_proof,
        witness::{AsyncWitnessReader, WitnessReader},
        ProofCompressed, TransferProofResult,
    },
    rpc::{
        compile_message, AsyncRpc, ComputeBudgetConfig, IndexerRpcConfig, Rpc,
        SettlementAccountValidation,
    },
};

use super::{validation::validate_fee_payer_pubkey, ZolanaClient};

/// A signed shielded transaction ready for proof assembly and submission.
///
/// Produced by `zolana_wallet::sign_shielded_transaction`; consumed by
/// [`ZolanaClient`]'s submission helpers.
pub struct SignedPrivateTransaction {
    pub transaction: SppProofInputs,
    pub settlement_transfers: Vec<TransactInterfaceTransferAccounts>,
}

impl<R> ZolanaClient<R> {
    /// Ask the configured prover for a default-ring Ed25519 transfer proof and
    /// verify it locally before returning its transaction wire encoding.
    pub async fn prove_confidential_transfer_result(
        &self,
        result: &TransferProofResult,
    ) -> Result<ProofCompressed, ClientError> {
        let proof = self.async_prover.prove_transfer(&result.inputs).await?;
        verify_confidential_transfer_proof(result, &proof)?;
        ProofCompressed::try_from(proof)
    }
}

impl<R: Rpc> ZolanaClient<R> {
    /// Fetch the input merkle proofs from the indexer and prove the transaction
    /// with the client's prover, returning the assembled `transact` instruction
    /// data ready for the [`Transact`] builder.
    ///
    /// `authority` completes the witness: the assembled inputs carry no
    /// nullifier secret, and it fills in the ones its owner holds.
    pub fn prove_transact(
        &self,
        proof_inputs: SppProofInputs,
        config: Option<IndexerRpcConfig>,
        authority: &dyn ProofAuthority,
    ) -> Result<TransactIxData, ClientError> {
        let commitments = proof_inputs.input_utxo_hashes()?;
        let witnesses = self.blocking_indexer().input_witnesses(
            &commitments,
            &proof_inputs.dummy_nullifiers(),
            config,
        )?;
        self.blocking_prover().prove_transact(
            proof_inputs,
            &witnesses.spend_proofs,
            &witnesses.dummy_nullifier_proofs,
            authority,
        )
    }

    /// Fetches the blockhash itself, after proving rather than before.
    ///
    /// Callers used to fetch one and hand it in, which put a multi-second proof
    /// between the blockhash and the send. Under load that window exceeded the
    /// blockhash lifetime and the transaction was rejected at submission,
    /// having already paid for the sync and the proof: an 80-worker run lost
    /// 297 of 337 transfers to "Blockhash not found".
    ///
    /// `R: Sync` because the two proof fetches below share the indexer across
    /// scoped threads.
    pub fn finish_submission_unsigned_sync(
        &self,
        signed: &SignedPrivateTransaction,
        fee_payer: Pubkey,
        authority: &dyn ProofAuthority,
    ) -> Result<VersionedMessage, ClientError>
    where
        R: Sync,
    {
        validate_fee_payer_pubkey(&signed.transaction.payer, fee_payer)?;
        let owner_signers = signed.transaction.owner_signer_pubkeys()?;
        let commitments = signed.transaction.input_utxo_hashes()?;
        // The overlap this used to hand-roll lives in the reader now, which
        // runs all the round trips together rather than two.
        let witnesses = self.blocking_indexer().input_witnesses(
            &commitments,
            &signed.transaction.dummy_nullifiers(),
            None,
        )?;
        let mut assembled = assemble(
            signed.transaction.clone(),
            &witnesses.spend_proofs,
            &witnesses.dummy_nullifier_proofs,
        )?;
        let proof = {
            let _t = crate::prover::timing::Phase::start("prove_transfer", 0);
            assembled.prove(self.blocking_prover(), authority)?
        };
        // Last thing before building, so the blockhash is as young as it can be
        // when the transaction reaches the cluster.
        let (recent_blockhash, _) = self.rpc().get_latest_blockhash()?;
        let trees = transact_trees(&assembled, &signed.transaction);
        build_unsigned_message(
            self.compute_budget(),
            fee_payer,
            trees,
            owner_signers,
            signed.settlement_transfers.clone(),
            assembled.with_proof(proof),
            recent_blockhash,
        )
    }
}

impl<R: AsyncRpc> ZolanaClient<R> {
    pub async fn finish_submission_unsigned(
        &self,
        signed: &SignedPrivateTransaction,
        fee_payer: Pubkey,
        recent_blockhash: Hash,
        authority: &dyn ProofAuthority,
    ) -> Result<VersionedMessage, ClientError> {
        validate_fee_payer_pubkey(&signed.transaction.payer, fee_payer)?;
        let owner_signers = signed.transaction.owner_signer_pubkeys()?;
        let commitments = signed.transaction.input_utxo_hashes()?;
        let witnesses = AsyncWitnessReader::input_witnesses(
            &self.async_indexer,
            &commitments,
            &signed.transaction.dummy_nullifiers(),
            None,
        )
        .await?;
        let mut assembled = assemble(
            signed.transaction.clone(),
            &witnesses.spend_proofs,
            &witnesses.dummy_nullifier_proofs,
        )?;
        let inputs = &mut assembled.prover_inputs;
        authority.complete_inputs(&mut inputs.inputs)?;
        let proof = self.async_prover.prove_transfer(inputs).await?;
        verify_confidential_transfer_inputs(inputs, assembled.public_input_hash, &proof)?;
        let proof = ProofCompressed::try_from(proof)?.to_transact_proof();
        let trees = transact_trees(&assembled, &signed.transaction);
        build_unsigned_message(
            self.compute_budget(),
            fee_payer,
            trees,
            owner_signers,
            signed.settlement_transfers.clone(),
            assembled.with_proof(proof),
            recent_blockhash,
        )
    }
}

/// The trees a `Transact` names, as the raw ids everything upstream carries.
/// The accounts are derived here, at the one point the instruction needs them.
struct TransactTrees {
    /// The trees the inputs are nullified in, one per `tree_contexts` entry and
    /// in that order, which is the order the builder pairs them up in.
    input_tree_ids: Vec<u16>,
    output_tree_id: u16,
}

/// Read both from the transaction itself: assembly declared the input trees in
/// the order it emitted their contexts, and the output tree is the id every
/// output commitment was hashed under. Nothing the client holds on the side can
/// disagree with either.
fn transact_trees(assembled: &AssembledTransfer, transaction: &SppProofInputs) -> TransactTrees {
    TransactTrees {
        input_tree_ids: assembled.input_tree_ids.clone(),
        output_tree_id: transaction.output_tree_id,
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
    let transact_ix = Transact {
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
    }
    .instruction();
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
