//! Merging a wallet's UTXOs. A merge takes up to 52 plain UTXOs of one owner,
//! one asset and one tree, and appends one UTXO holding their sum. The owner
//! signs nothing: once its user record enables merging, a merge proved with its
//! nullifier secret is valid from any fee payer.

use std::sync::Arc;

use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Signer;
use solana_signature::Signature;
use spr_instruction::instruction::MergeTransact;
use spr_interface::{instruction::instruction_data::merge_transact::MergeTransactIxData, pda};
use spr_keypair::ShieldedAddress;
use spr_transaction::instructions::merge::MergeProofInputs;
use spr_user_registry_interface::{user_record_pda, MergeEncryptionScheme, UserRecord};

use crate::{
    error::ClientError,
    prover::{merge::MergeProofResult, requests, witness::InputWitnesses, ProofCompressed, Prover},
    rpc::{compile_message, sign_transaction, AsyncRpc, ComputeBudgetConfig},
    user_registry::fetch_user_record_optional_checked_async,
};

use super::{
    prove_on_blocking_pool, AsyncIndexer, AsyncSprClient, BlockingIndexer, BlockingRpc, SprClient,
    UnsignedMessage,
};

/// Compute-unit ceiling of a `merge_transact`. The widest shape, "Merge 52x1"
/// in `program-tests/shielded-pool/CU_BENCHMARK.md`, measures 293,555 CU; the
/// ceiling is the transaction-wide maximum.
pub const MERGE_CU_LIMIT: u32 = 1_400_000;

/// Encrypted merge inputs and the capability that prepares their proof.
pub struct MergeProofRequest<'a> {
    merge: MergeProofInputs,
    keys: &'a dyn crate::authority::MergeKeys,
    prover: Option<Arc<dyn Prover>>,
}

/// A merge with an attached proof and a checked owner record, ready for any fee
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
    /// Build a message without RPC access. The payer can change without reproving.
    pub fn build_solana_message(
        &self,
        fee_payer: Address,
        blockhash: Hash,
        last_valid_block_height: u64,
        compute_budget: ComputeBudgetConfig,
    ) -> Result<UnsignedMessage, ClientError> {
        Ok(UnsignedMessage {
            message: compile_message(
                &fee_payer,
                &[self.instruction(fee_payer)],
                blockhash,
                compute_budget,
            )?,
            last_valid_block_height,
        })
    }

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

impl<'a> MergeProofRequest<'a> {
    pub fn new(
        merge: MergeProofInputs,
        keys: &'a dyn crate::authority::MergeKeys,
    ) -> Result<Self, ClientError> {
        let address = keys.address()?;
        if merge.signing_pubkey != address.signing_pubkey {
            return Err(ClientError::MergeSigningKeyMismatch);
        }
        input_tree_id(&merge)?;
        Ok(Self {
            merge,
            keys,
            prover: None,
        })
    }

    #[must_use]
    pub fn with_prover(mut self, prover: Arc<dyn Prover>) -> Self {
        self.prover = Some(prover);
        self
    }

    /// Read the owner's merge registration without fetching chain proofs.
    pub async fn fetch_record<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncSprClient<R, I>,
    ) -> Result<UserRecord, ClientError> {
        let address = self.keys.address()?;
        let owner = Address::new_from_array(address.signing_pubkey.confidential_view_tag()?);
        fetch_user_record_optional_checked_async(client.rpc(), owner)
            .await?
            .ok_or(ClientError::UserRegistryRecordNotFound {
                owner,
                record: user_record_pda(&owner).0,
            })
    }

    pub async fn fetch_input_proofs<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncSprClient<R, I>,
    ) -> Result<InputWitnesses, ClientError> {
        client
            .indexer
            .input_witnesses(
                &self.merge.input_utxo_hashes()?,
                &self.merge.dummy_nullifiers(),
                Some(client.indexer_config),
            )
            .await
    }

    /// Check the fetched record and construct completed merge inputs without I/O.
    pub fn build(
        &self,
        record: &UserRecord,
        proofs: InputWitnesses,
    ) -> Result<MergeProofResult, ClientError> {
        let address = self.keys.address()?;
        if address.signing_pubkey != self.merge.signing_pubkey {
            return Err(ClientError::MergeSigningKeyMismatch);
        }
        let owner = Address::new_from_array(address.signing_pubkey.confidential_view_tag()?);
        check_merge_record(record, owner, &address)?;
        ensure_on_tree(&proofs, pda::tree(input_tree_id(&self.merge)?))?;
        crate::prover::merge::assemble_merge(
            self.merge.clone(),
            self.keys,
            proofs.spend_proofs,
            proofs.dummy_nullifier_proofs,
            None,
        )
    }

    /// Invoke the selected prover with completed merge inputs. No chain reads.
    pub async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncSprClient<R, I>,
        merge: &MergeProofResult,
    ) -> Result<crate::Proof, ClientError> {
        let request = requests::merge(&merge.inputs)?;
        match &self.prover {
            Some(prover) => match prover.server_client() {
                Some(server) => server.prove(&request).await,
                None => prove_on_blocking_pool(Arc::clone(prover), request).await,
            },
            None => client.prove_request(request).await,
        }
    }

    pub fn with_proof(
        &self,
        merge: MergeProofResult,
        proof: crate::Proof,
    ) -> Result<ProvedMerge, ClientError> {
        let owner = Address::new_from_array(self.merge.signing_pubkey.confidential_view_tag()?);
        Ok(ProvedMerge {
            input_tree_id: input_tree_id(&self.merge)?,
            output_tree_id: self.merge.output_tree_id,
            user_record: user_record_pda(&owner).0,
            data: merge.instruction_data(ProofCompressed::try_from(proof)?.to_merge_proof()?),
            output_hash: merge.output_hash,
        })
    }

    /// Fetch and prove alongside the blockhash request, then build the unsigned message.
    pub async fn fetch_and_prove<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncSprClient<R, I>,
        payer: Address,
    ) -> Result<UnsignedMessage, ClientError> {
        let proving = async {
            let (record, input_proofs) =
                tokio::try_join!(self.fetch_record(client), self.fetch_input_proofs(client))?;
            let merge = self.build(&record, input_proofs)?;
            let proof = self.prove(client, &merge).await?;
            self.with_proof(merge, proof)
        };
        let (proved, (blockhash, height)) =
            tokio::try_join!(proving, client.get_latest_blockhash())?;
        let mut budget = client.compute_budget();
        budget.cu_limit = MERGE_CU_LIMIT;
        proved.build_solana_message(payer, blockhash, height, budget)
    }

    pub fn fetch_record_sync<R: BlockingRpc, I: BlockingIndexer>(
        &self,
        client: &SprClient<R, I>,
    ) -> Result<UserRecord, ClientError> {
        client.block_on(self.fetch_record(&client.client))
    }

    pub fn fetch_input_proofs_sync<R: BlockingRpc, I: BlockingIndexer>(
        &self,
        client: &SprClient<R, I>,
    ) -> Result<InputWitnesses, ClientError> {
        client.block_on(self.fetch_input_proofs(&client.client))
    }

    pub fn fetch_and_prove_sync<R: BlockingRpc, I: BlockingIndexer>(
        &self,
        client: &SprClient<R, I>,
        payer: Address,
    ) -> Result<UnsignedMessage, ClientError> {
        client.block_on(self.fetch_and_prove(&client.client, payer))
    }

    /// Prove, sign with `fee_payer`, send through `client` and wait until the
    /// merge is confirmed and indexed.
    pub async fn prove_and_send<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncSprClient<R, I>,
        fee_payer: &dyn Signer,
    ) -> Result<Signature, ClientError> {
        let payer = fee_payer
            .try_pubkey()
            .map_err(|error| ClientError::SolanaTransactionSigning(error.to_string()))?;
        let unsigned = self.fetch_and_prove(client, payer).await?;
        let signature = client
            .process_transaction(sign_transaction(unsigned.message, &[fee_payer])?)
            .await?;
        client.confirm_private_transaction(signature).await?;
        Ok(signature)
    }

    /// See [`Self::prove`].
    pub fn prove_sync<R: BlockingRpc, I: BlockingIndexer>(
        &self,
        client: &SprClient<R, I>,
        merge: &MergeProofResult,
    ) -> Result<crate::Proof, ClientError> {
        client.block_on(self.prove(&client.client, merge))
    }

    /// See [`Self::prove_and_send`].
    pub fn prove_and_send_sync<R: BlockingRpc, I: BlockingIndexer>(
        &self,
        client: &SprClient<R, I>,
        fee_payer: &dyn Signer,
    ) -> Result<Signature, ClientError> {
        client.block_on(self.prove_and_send(&client.client, fee_payer))
    }
}

/// Whether `record`, `owner`'s user record, lets `address` merge: the record
/// selects the PoseidonCtrV1 merge encryption scheme (the one this client
/// encrypts with; the program rejects any other), and the record holds
/// `address`'s signing, nullifier and viewing keys. The program checks all but the viewing key, so a mismatch caught here
/// saves a proof; a viewing key mismatch means the local keys are stale.
pub fn check_merge_record(
    record: &UserRecord,
    owner: Address,
    address: &ShieldedAddress,
) -> Result<(), ClientError> {
    if record.merge_encryption != MergeEncryptionScheme::PoseidonCtrV1 {
        return Err(ClientError::MergeEncryptionSchemeUnsupported { owner });
    }
    let signing = address.signing_pubkey;
    let signing_matches = signing.confidential_view_tag()? == owner.to_bytes();
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
/// [`MergeTransaction::new`]: spr_transaction::instructions::merge::MergeTransaction::new
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
