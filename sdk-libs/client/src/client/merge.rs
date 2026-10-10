//! Merging a wallet's UTXOs. A merge takes up to 54 plain UTXOs of one owner,
//! one asset and one tree, and appends one UTXO holding their sum. The owner
//! signs nothing: once its user record enables merging, a merge proved with its
//! nullifier secret is valid from any fee payer.

use std::sync::Arc;

use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Signer;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use zolana_interface::{instruction::instruction_data::merge_transact::MergeTransactIxData, pda};
use zolana_keypair::{Curve, NullifierKey, ShieldedAddress};
use zolana_program::instruction::MergeTransact;
use zolana_transaction::instructions::merge::MergeProofInputs;
use zolana_user_registry_interface::{user_record_pda, UserRecord};

use crate::{
    error::ClientError,
    prover::{
        merge::{MergeProofResult, MergeProver},
        requests,
        verify::MergeProofStatement,
        witness::InputWitnesses,
        ProofCompressed, Prover,
    },
    rpc::{compile_message, sign_transaction, AsyncRpc},
    user_registry::fetch_user_record_optional_checked_async,
};

use super::{
    prove_on_blocking_pool, AsyncIndexer, AsyncZolanaClient, BlockingIndexer, BlockingRpc,
    ZolanaClient,
};

/// Compute-unit ceiling of a `merge_transact`. The widest shape, "Merge 54x1"
/// in `program-tests/shielded-pool/CU_BENCHMARK.md`, measures 296,879 CU; the
/// ceiling is the transaction-wide maximum.
pub const MERGE_CU_LIMIT: u32 = 1_400_000;

/// A prepared merge on its way to the chain: whose record authorizes it, the
/// keys that prove it, and what proves it. The proof does not bind the fee
/// payer, so [`Self::prove`] stops at a [`ProvedMerge`] any payer can send;
/// [`Self::finish_unsigned`] builds the message a given payer signs, and
/// [`Self::send`] signs, sends and confirms it.
pub struct MergeSubmission<'a> {
    /// From [`MergeTransaction::encrypt`]. Give it an expiry
    /// ([`MergeTransaction::with_expiry`]): until it expires, anyone who holds
    /// the proof can submit it.
    ///
    /// [`MergeTransaction::encrypt`]: zolana_transaction::instructions::merge::MergeTransaction::encrypt
    /// [`MergeTransaction::with_expiry`]: zolana_transaction::instructions::merge::MergeTransaction::with_expiry
    pub merge: &'a MergeProofInputs,
    /// The Solana account whose user record enables merging.
    pub owner: Address,
    /// The owner's shielded address, checked against the record before
    /// proving.
    pub address: &'a ShieldedAddress,
    /// Proves the merge. The proof request carries it: a prover other than
    /// this process learns it, and with it every merged amount.
    pub nullifier_key: &'a NullifierKey,
    /// Proves this merge in place of the client's prover.
    pub prover: Option<Arc<dyn Prover>>,
}

/// A merge proved and verified against its owner's record, ready for any fee
/// payer: [`Self::instruction`] is its `merge_transact`, to put in any message.
#[derive(Clone, Debug)]
pub struct ProvedMerge {
    pub input_tree_id: u16,
    pub output_tree_id: u16,
    /// The owner's user record, which the proof is bound to.
    pub user_record: Address,
    pub data: MergeTransactIxData,
    /// The UTXO the merge appends to the output tree.
    pub output_hash: [u8; 32],
}

impl ProvedMerge {
    /// The `merge_transact` `payer` pays for and signs. It verifies a Groth16
    /// proof: give its transaction [`MERGE_CU_LIMIT`].
    pub fn instruction(&self, payer: Address) -> Instruction {
        MergeTransact {
            input_tree: pda::tree(self.input_tree_id),
            output_tree: pda::tree(self.output_tree_id),
            payer,
            user_record: self.user_record,
            data: self.data.clone(),
            cache: None,
        }
        .instruction()
    }
}

impl<'a> MergeSubmission<'a> {
    pub fn new(
        merge: &'a MergeProofInputs,
        owner: Address,
        address: &'a ShieldedAddress,
        nullifier_key: &'a NullifierKey,
    ) -> Self {
        Self {
            merge,
            owner,
            address,
            nullifier_key,
            prover: None,
        }
    }

    #[must_use]
    pub fn with_prover(mut self, prover: Arc<dyn Prover>) -> Self {
        self.prover = Some(prover);
        self
    }

    /// Check the owner's record, fetch the witness through `client`, prove
    /// with `client`'s prover or [`Self::prover`], and verify the proof.
    pub async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<ProvedMerge, ClientError> {
        let user_record = user_record_pda(&self.owner).0;
        let record = fetch_user_record_optional_checked_async(client.rpc(), self.owner)
            .await?
            .ok_or(ClientError::UserRegistryRecordNotFound {
                owner: self.owner,
                record: user_record,
            })?;
        check_merge_record(&record, self.owner, self.address)?;
        let input_tree_id = input_tree_id(self.merge)?;
        let commitments = self.merge.input_utxo_hashes()?;
        let witnesses = client
            .indexer
            .input_witnesses(&commitments, &self.merge.dummy_nullifiers(), None)
            .await?;
        ensure_on_tree(&witnesses, pda::tree(input_tree_id))?;
        let result = MergeProver {
            transaction: self.merge.clone(),
            nullifier_key: self.nullifier_key.clone(),
            proofs: witnesses.spend_proofs,
            dummy_nullifier_proofs: witnesses.dummy_nullifier_proofs,
            cache: None,
        }
        .build()?;
        let proof = match &self.prover {
            Some(prover) => {
                prove_on_blocking_pool(Arc::clone(prover), requests::merge(&result.inputs)?).await?
            }
            None => client.prove_merge(&result.inputs).await?,
        };
        verify(&result, &proof)?;
        Ok(ProvedMerge {
            input_tree_id,
            output_tree_id: self.merge.output_tree_id,
            user_record,
            data: result.instruction_data(ProofCompressed::try_from(proof)?.to_merge_proof()?),
            output_hash: result.output_hash,
        })
    }

    /// The unsigned v1 message of this merge, which `fee_payer` pays for and
    /// signs alone. The blockhash is fetched after proving.
    pub async fn finish_unsigned<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
        fee_payer: Address,
    ) -> Result<VersionedMessage, ClientError> {
        let merge = self.prove(client).await?.instruction(fee_payer);
        let mut compute_budget = client.compute_budget();
        compute_budget.cu_limit = MERGE_CU_LIMIT;
        // Last thing before building, so the blockhash is as young as it can be.
        let (recent_blockhash, _) = client.rpc().get_latest_blockhash().await?;
        compile_message(
            &fee_payer,
            core::slice::from_ref(&merge),
            recent_blockhash,
            compute_budget,
        )
    }

    /// Prove, sign with `fee_payer`, send through `client` and wait until the
    /// merge is confirmed and indexed.
    pub async fn send<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
        fee_payer: &dyn Signer,
    ) -> Result<Signature, ClientError> {
        let message = self.finish_unsigned(client, fee_payer.pubkey()).await?;
        let signature = client
            .process_transaction(sign_transaction(message, &[fee_payer])?)
            .await?;
        client.confirm_private_transaction(signature).await?;
        Ok(signature)
    }

    /// See [`Self::prove`].
    pub fn prove_sync<R: BlockingRpc, I: BlockingIndexer>(
        &self,
        client: &ZolanaClient<R, I>,
    ) -> Result<ProvedMerge, ClientError> {
        client.block_on(self.prove(&client.client))
    }

    /// See [`Self::finish_unsigned`].
    pub fn finish_unsigned_sync<R: BlockingRpc, I: BlockingIndexer>(
        &self,
        client: &ZolanaClient<R, I>,
        fee_payer: Address,
    ) -> Result<VersionedMessage, ClientError> {
        client.block_on(self.finish_unsigned(&client.client, fee_payer))
    }

    /// See [`Self::send`].
    pub fn send_sync<R: BlockingRpc, I: BlockingIndexer>(
        &self,
        client: &ZolanaClient<R, I>,
        fee_payer: &dyn Signer,
    ) -> Result<Signature, ClientError> {
        client.block_on(self.send(&client.client, fee_payer))
    }
}

/// Whether `record`, `owner`'s user record, lets `address` merge: merging is
/// enabled, and the record holds `address`'s signing, nullifier and viewing
/// keys. The program checks all but the viewing key, so a mismatch caught here
/// saves a proof; a viewing key mismatch means the local keys are stale.
pub fn check_merge_record(
    record: &UserRecord,
    owner: Address,
    address: &ShieldedAddress,
) -> Result<(), ClientError> {
    if !record.merging_enabled {
        return Err(ClientError::MergeDisabled { owner });
    }
    let signing = address.signing_pubkey;
    let signing_matches = match signing.curve()? {
        Curve::P256 => record.owner_p256 == Some(*signing.as_p256()?.as_bytes()),
        // The ed25519 rail takes the signing identity from the record's
        // Solana `owner`; a PDA owner is the same.
        Curve::Ed25519 | Curve::Pda => {
            record.owner_p256.is_none() && signing.confidential_view_tag()? == owner.to_bytes()
        }
    };
    if !signing_matches {
        return Err(ClientError::MergeSigningKeyMismatch);
    }
    if record.nullifier_pubkey != address.nullifier_pubkey {
        return Err(ClientError::MergeNullifierKeyMismatch);
    }
    if record.viewing_pubkey != *address.viewing_pubkey.as_bytes() {
        return Err(ClientError::MergeViewingKeyMismatch { owner });
    }
    Ok(())
}

/// The one tree a merge's inputs sit in; [`MergeTransaction::new`] refuses
/// inputs on several.
///
/// [`MergeTransaction::new`]: zolana_transaction::instructions::merge::MergeTransaction::new
fn input_tree_id(merge: &MergeProofInputs) -> Result<u16, ClientError> {
    merge
        .input_utxos
        .first()
        .map(|input| input.tree_id)
        .ok_or(ClientError::NoInputs)
}

/// A merge proof verifies only against the tree its witness came from.
fn ensure_on_tree(witnesses: &InputWitnesses, input_tree: Address) -> Result<(), ClientError> {
    let trees = witnesses
        .spend_proofs
        .iter()
        .flat_map(|proof| {
            [
                proof.state.merkle_context.tree,
                proof.nullifier.merkle_context.tree,
            ]
        })
        .chain(
            witnesses
                .dummy_nullifier_proofs
                .iter()
                .map(|proof| proof.merkle_context.tree),
        );
    for proof_tree in trees {
        if proof_tree != input_tree {
            return Err(ClientError::MergeInputTreeMismatch {
                proof_tree: proof_tree.to_bytes(),
                input_tree: input_tree.to_bytes(),
            });
        }
    }
    Ok(())
}

/// A remote prover's proof is checked before anyone pays for it.
fn verify(result: &MergeProofResult, proof: &crate::prover::Proof) -> Result<(), ClientError> {
    MergeProofStatement {
        n_inputs: result.nullifiers.len(),
        public_input_hash: result.public_input_hash,
    }
    .verify(proof)
}
