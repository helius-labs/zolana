//! Merging a wallet's UTXOs. A merge takes up to 54 plain UTXOs of one owner,
//! one asset and one tree, and appends one UTXO holding their sum. The owner
//! signs nothing: once its user record enables merging, a merge proved with its
//! nullifier secret is valid from any fee payer.

use std::sync::Arc;

use solana_address::Address;
use solana_keypair::Signer;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use zolana_interface::pda;
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
/// keys that prove it, who pays, and what proves it.
/// [`Self::finish_unsigned`] builds the message the fee payer signs;
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
    /// proving: the program checks the same keys after.
    pub address: &'a ShieldedAddress,
    /// Proves the merge. The proof request carries it: a prover other than
    /// this process learns it, and with it every merged amount.
    pub nullifier_key: &'a NullifierKey,
    pub fee_payer: Address,
    /// Proves this merge in place of the client's prover.
    pub prover: Option<Arc<dyn Prover>>,
}

/// A proved merge's message, unsigned, and the UTXO it appends.
pub struct UnsignedMerge {
    pub message: VersionedMessage,
    pub output_hash: [u8; 32],
}

impl<'a> MergeSubmission<'a> {
    pub fn new(
        merge: &'a MergeProofInputs,
        owner: Address,
        address: &'a ShieldedAddress,
        nullifier_key: &'a NullifierKey,
        fee_payer: Address,
    ) -> Self {
        Self {
            merge,
            owner,
            address,
            nullifier_key,
            fee_payer,
            prover: None,
        }
    }

    #[must_use]
    pub fn with_prover(mut self, prover: Arc<dyn Prover>) -> Self {
        self.prover = Some(prover);
        self
    }

    /// The unsigned v1 message of this merge, proved through `client`'s
    /// prover or [`Self::prover`], with the witness `client` fetches. The
    /// blockhash is fetched after proving.
    pub async fn finish_unsigned<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<UnsignedMerge, ClientError> {
        let record = fetch_user_record_optional_checked_async(client.rpc(), self.owner)
            .await?
            .ok_or(ClientError::UserRegistryRecordNotFound {
                owner: self.owner,
                record: user_record_pda(&self.owner).0,
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
        let merge = MergeTransact {
            input_tree: pda::tree(input_tree_id),
            output_tree: pda::tree(self.merge.output_tree_id),
            payer: self.fee_payer,
            user_record: user_record_pda(&self.owner).0,
            data: result.instruction_data(ProofCompressed::try_from(proof)?.to_merge_proof()?),
            cache: None,
        }
        .instruction();
        let mut compute_budget = client.compute_budget();
        compute_budget.cu_limit = MERGE_CU_LIMIT;
        // Last thing before building, so the blockhash is as young as it can be.
        let (recent_blockhash, _) = client.rpc().get_latest_blockhash().await?;
        Ok(UnsignedMerge {
            message: compile_message(
                &self.fee_payer,
                core::slice::from_ref(&merge),
                recent_blockhash,
                compute_budget,
            )?,
            output_hash: result.output_hash,
        })
    }

    /// Prove, sign with `signers` (the fee payer), send through `client` and
    /// wait until the merge is confirmed and indexed.
    pub async fn send<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
        signers: &[&dyn Signer],
    ) -> Result<Signature, ClientError> {
        let unsigned = self.finish_unsigned(client).await?;
        let signature = client
            .process_transaction(sign_transaction(unsigned.message, signers)?)
            .await?;
        client.confirm_private_transaction(signature).await?;
        Ok(signature)
    }

    /// See [`Self::finish_unsigned`].
    pub fn finish_unsigned_sync<R: BlockingRpc, I: BlockingIndexer>(
        &self,
        client: &ZolanaClient<R, I>,
    ) -> Result<UnsignedMerge, ClientError> {
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

/// Whether `record`, `owner`'s user record, lets `address` merge: merging is
/// enabled, and the record holds `address`'s signing, nullifier and viewing
/// keys. The program checks the same, so a mismatch caught here saves a proof.
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

/// The one tree a merge's inputs sit in; [`MergeTransaction::new`] admits no
/// other.
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

#[cfg(test)]
mod tests {
    use crate::{MerkleContext, MerkleProof, NonInclusionProof, SpendProof};

    use super::*;

    fn non_inclusion(tree: Address) -> NonInclusionProof {
        NonInclusionProof {
            leaf: [3; 32],
            merkle_context: MerkleContext { tree_type: 0, tree },
            path: Vec::new(),
            low_element: [0; 32],
            low_element_index: 0,
            high_element: [4; 32],
            high_element_index: 0,
            root: [5; 32],
            root_seq: 0,
            root_index: 0,
        }
    }

    fn witnesses(state: Address, nullifier: Address, dummy: Address) -> InputWitnesses {
        InputWitnesses {
            spend_proofs: vec![SpendProof {
                state: MerkleProof {
                    leaf: [1; 32],
                    merkle_context: MerkleContext {
                        tree_type: 0,
                        tree: state,
                    },
                    path: Vec::new(),
                    leaf_index: 0,
                    root: [2; 32],
                    root_seq: 0,
                    root_index: 0,
                },
                nullifier: non_inclusion(nullifier),
            }],
            dummy_nullifier_proofs: vec![non_inclusion(dummy)],
        }
    }

    #[test]
    fn every_proof_of_a_merge_witness_is_on_the_input_tree() {
        let tree = Address::new_from_array([7; 32]);
        let other = Address::new_from_array([8; 32]);
        ensure_on_tree(&witnesses(tree, tree, tree), tree).expect("one tree");
        for witnesses in [
            witnesses(other, tree, tree),
            witnesses(tree, other, tree),
            witnesses(tree, tree, other),
        ] {
            assert!(matches!(
                ensure_on_tree(&witnesses, tree),
                Err(ClientError::MergeInputTreeMismatch { proof_tree, input_tree })
                    if proof_tree == other.to_bytes() && input_tree == tree.to_bytes()
            ));
        }
    }
}
