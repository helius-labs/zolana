//! One transfer pipeline for both rails. The owner signs its spends, the
//! delegate moves notes on the ring-authority rail with the recovered key.

mod delegate;
mod owner;

use solana_address::Address;
use solana_instruction::Instruction;
use zolana_client::{
    attach_input_proofs, input_utxos_from_nullifiers,
    prover::{
        indexed::{
            IndexedPolicyData, IndexedPolicyRequest, IndexedTransferPreparation,
            IndexedTransferRail, PreparedIndexedTransfer,
        },
        requests,
    },
    AsyncIndexer, AsyncRpc, AsyncWitnessReader, AsyncZolanaClient, ClientError, IndexerRpcConfig,
    Proof, ProofAuthority, ProofCompressed, ProveRequest, RingAuthorityProver, RingTransferProver,
    TransferInput, TransferInputs,
};
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::{
    instruction::{instruction_data::transact::TreeContext, CircuitId, TransactIxData},
    N_PUBLIC_SLOTS,
};
use zolana_keypair::{NullifierKey, ViewingKey};
use zolana_transaction::{
    instructions::transact::{SppProofInputs, SppProofOutputUtxo},
    utxo::SppProofInputUtxo,
};

pub use self::{
    delegate::{ring_authority_width, DelegateOutput, DelegateTransferInput, Delegated},
    owner::{CustomRingTransferInput, Owner},
};
pub(crate) use owner::{frame_dummy_outputs, record_input_position};

use crate::{
    audit::{PendingCustomRingProof, PolicyProof},
    entry::zero_nullifier_key,
    escrow::KeyRegistry,
    heap::boxed,
    projection::retry_projection_lag,
    prover::{RingCircuit, RingRequest},
    request::{BaseBody, PolicyEnvelope},
    submission::BoundRoot,
    to_instruction_proof,
    trees::{spend_trees, SpendTrees},
    witness::WitnessInput,
    CustomRing, CustomRingDelegateTransact, CustomRingProof, CustomRingTransact, PinnedPolicy,
    PolicyReads, PolicyTreeContext, RingError, RingIdentity, VelocityProofInput,
};
use zolana_program::instruction::TransactInterfaceTransferAccounts;

mod sealed {
    pub trait Sealed {}
}

/// Who authorizes the spends, the owner or the ring's delegate with the recovered key.
pub trait Rail: sealed::Sealed + Send + Sync {
    #[doc(hidden)]
    fn kind(&self) -> RailKind<'_>;
}

#[doc(hidden)]
pub enum RailKind<'a> {
    Owner(&'a Owner<'a>),
    Delegated(&'a Delegated<'a>),
}

#[must_use = "prove or discard the transfer explicitly"]
pub struct RingTransfer<R: Rail> {
    ring: CustomRing,
    rail: R,
    cosigner: Option<Address>,
    indexer_config: Option<IndexerRpcConfig>,
}

pub type CustomRingTransfer<'a> = RingTransfer<Owner<'a>>;
pub type DelegateTransfer<'a> = RingTransfer<Delegated<'a>>;

#[must_use = "build or submit the proven transfer"]
pub struct ProvenRingTransfer {
    pub tx_viewing_key: ViewingKey,
    pub data: TransactIxData,
    pub proof: CustomRingProof,
    /// `None` on an audit-only ring.
    pub policy: Option<PolicyReads>,
    pub cosigner: Option<Address>,
    /// The velocity statement demands the co-signer, the caller signs with it.
    pub approval_required: bool,
    /// Padding included.
    pub outputs: Vec<SppProofOutputUtxo>,
    /// The eddsa owners of the spent UTXOs, empty on the delegate rail.
    pub owner_signers: Vec<Address>,
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    /// The window a windowed statement proves, zero otherwise.
    window_index: u64,
    payer: Address,
    delegate: Option<Address>,
    trees: SpendTrees,
    ring: CustomRing,
}

pub type ProvenTransfer = ProvenRingTransfer;
pub type ProvenDelegateTransfer = ProvenRingTransfer;

/// A transfer past auditor encryption, the auditor message already in `messages`.
pub(crate) struct Staged {
    pub proof_inputs: SppProofInputs,
    pub pending: PendingCustomRingProof,
    pub tx_viewing_key: ViewingKey,
    pub pinned: Option<Box<PinnedPolicy>>,
    /// `None` commits the pinned rows without charging them.
    pub velocity: Option<VelocityProofInput>,
    /// The windowed record rides at the last real input and the last output.
    pub record: Option<CompressedDisclosure>,
    pub authority: TransferAuthority,
    pub key_registry: Option<KeyRegistry>,
    pub owner_signers: Vec<Address>,
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    pub delegate: Option<Address>,
}

#[derive(Clone, Copy)]
pub(crate) struct CompressedDisclosure {
    pub transaction_salt: [u8; 16],
    pub counters_disclosure_hash: [u8; 32],
}

pub(crate) struct TransferAuthority {
    pub owner: Option<NullifierKey>,
    /// Position of the namespace-owned spend record, it nullifies under the zero key.
    pub spend_record: Option<usize>,
}

impl ProofAuthority for TransferAuthority {
    fn complete_inputs(&self, inputs: &mut [TransferInput]) -> Result<(), ClientError> {
        if let Some(position) = self.spend_record {
            let record = inputs.get_mut(position).ok_or(ClientError::NoInputs)?;
            zero_nullifier_key().complete_inputs(std::slice::from_mut(record))?;
        }
        match &self.owner {
            Some(owner) => owner.complete_inputs(inputs),
            None => Ok(()),
        }
    }
}

impl<R: Rail> RingTransfer<R> {
    #[must_use = "use the updated transfer"]
    pub fn with_cosigner(mut self, cosigner: Address) -> Self {
        self.cosigner = Some(cosigner);
        self
    }

    /// The policy entries wait until the indexer persisted `config.require_slot`.
    #[must_use = "use the updated transfer"]
    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.indexer_config = Some(config);
        self
    }

    pub async fn prove<P: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<P, I>,
    ) -> Result<ProvenRingTransfer, RingError> {
        retry_projection_lag(|| self.prove_once(client)).await
    }

    async fn prove_once<P: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<P, I>,
    ) -> Result<ProvenRingTransfer, RingError> {
        let config = self
            .ring
            .config(client)
            .await?
            .ok_or(RingError::MissingRingConfig)?;
        let staged = match self.rail.kind() {
            RailKind::Owner(owner) => boxed(|| owner.stage(self.ring, client, &config)).await?,
            RailKind::Delegated(delegated) => {
                boxed(|| delegated.stage(self.ring, client, &config)).await?
            }
        };
        check_distinct(&staged.proof_inputs.input_utxos)?;
        let inputs = &staged.proof_inputs;
        // A missing or foreign tree fails before the indexer serves proofs against it.
        let trees = spend_trees(client, &inputs.input_utxos, inputs.output_tree_id).await?;
        let indexed = client.indexed_prover().is_some();
        let spp = Spp::witness(self, client, &staged, &trees).await?;
        let policy = match &staged.pinned {
            Some(pinned) => Some(boxed(|| self.policy(client, &staged, pinned, indexed)).await?),
            None => None,
        };
        if policy
            .as_ref()
            .is_some_and(|policy| policy.approval_required)
            && self.cosigner.is_none()
        {
            return Err(RingError::ApprovalWithoutCoSigner);
        }
        let private_tx_hash = spp.private_tx_hash();
        let tier = match policy {
            Some(policy) => Tier::Policy(Box::new(policy.finish(staged.pending, private_tx_hash)?)),
            None => Tier::Base(Box::new(staged.pending.finish_base(private_tx_hash)?)),
        };
        // Neither proof is an input to the other, the requests go out together.
        let ((data, outputs), (proof, policy, approval_required)) = futures::try_join!(
            boxed(|| spp.prove(client, &staged.proof_inputs)),
            boxed(|| tier.prove(client)),
        )?;
        Ok(ProvenRingTransfer {
            tx_viewing_key: staged.tx_viewing_key,
            data,
            proof: to_instruction_proof(proof)?,
            policy,
            cosigner: self.cosigner,
            approval_required,
            outputs,
            owner_signers: staged.owner_signers,
            interface_transfer_accounts: staged.interface_transfer_accounts,
            window_index: staged
                .record
                .and(staged.velocity)
                .map_or(0, |velocity| velocity.window_index),
            payer: staged.proof_inputs.payer,
            delegate: staged.delegate,
            trees,
            ring: self.ring,
        })
    }

    async fn policy<P: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<P, I>,
        staged: &Staged,
        pinned: &PinnedPolicy,
        indexed: bool,
    ) -> Result<PolicyStatement, RingError> {
        let inputs = &staged.proof_inputs;
        let velocity = match staged.velocity {
            Some(velocity) => velocity,
            None => committed(self.ring, pinned)?,
        };
        let witness = WitnessInput {
            pinned,
            inputs: &inputs.input_utxos,
            outputs: &inputs.output_utxos,
            output_tree_id: inputs.output_tree_id,
            private_tx_blinding: inputs.private_tx_blinding()?,
            velocity,
            record: staged.record.is_some(),
            key_registry: staged.key_registry,
            indexer_config: self.indexer_config,
        }
        .build(client, indexed)
        .await?;
        let circuit = match (staged.delegate, staged.record) {
            (Some(_), _) => RingCircuit::DelegatePolicy,
            (None, Some(_)) => RingCircuit::CompressedPolicy,
            (None, None) => RingCircuit::Policy,
        };
        Ok(PolicyStatement {
            approval_required: witness.velocity.approval_required,
            reads: witness.reads(),
            witness,
            policy_hash: pinned.config.policy_hash,
            circuit,
            compressed: staged.record,
        })
    }
}

/// Boxed, staging holds the pinned table across its later reads.
async fn pinned_policy(
    ring: CustomRing,
    client: &(impl AsyncRpc + ?Sized),
) -> Result<Box<PinnedPolicy>, RingError> {
    let pinned = ring.pinned_policy(client).await?;
    Ok(Box::new(pinned.ok_or(RingError::MissingPolicyConfig)?))
}

/// A record-free rail evaluates every money slot while committing the pinned rows.
fn committed(ring: CustomRing, pinned: &PinnedPolicy) -> Result<VelocityProofInput, RingError> {
    let rows = pinned.table.velocity();
    let mut velocity =
        VelocityProofInput::off(RingIdentity::new(ring, pinned.config.namespace_owner_hash)?);
    velocity.window_slots = pinned.table.window_slots();
    velocity.row_count = rows.len() as u8;
    velocity.rows[..rows.len()].copy_from_slice(rows);
    Ok(velocity)
}

/// Each real input spends once, a repeated nullifier fails on chain after proving.
fn check_distinct(inputs: &[SppProofInputUtxo]) -> Result<(), RingError> {
    let real: Vec<_> = inputs.iter().filter(|input| !input.is_dummy()).collect();
    match real.iter().enumerate().find(|(index, input)| {
        real[..*index]
            .iter()
            .any(|earlier| earlier.nullifier == input.nullifier)
    }) {
        Some((_, input)) => Err(RingError::DuplicateInput {
            nullifier: input.nullifier,
        }),
        None => Ok(()),
    }
}

struct PolicyStatement {
    witness: Box<crate::witness::CustomRingWitness>,
    reads: PolicyReads,
    approval_required: bool,
    policy_hash: [u8; 32],
    circuit: RingCircuit,
    compressed: Option<CompressedDisclosure>,
}

impl PolicyStatement {
    fn finish(
        self,
        pending: PendingCustomRingProof,
        private_tx_hash: [u8; 32],
    ) -> Result<PolicyRequest, RingError> {
        let PolicyProof {
            mut body,
            mut indexed,
        } = pending.finish(private_tx_hash, self.witness, &self.policy_hash)?;
        // The compressed circuit folds the counters disclosure after the policy chain.
        if let Some(compressed) = self.compressed {
            if body.witness.velocity.window_slots == 0 {
                return Err(RingError::CompressedWithoutWindow);
            }
            body.public_input_hash = Poseidon::hashv(&[
                &body.public_input_hash,
                &compressed.counters_disclosure_hash,
            ])?;
            if let Some(indexed) = &mut indexed {
                indexed
                    .public_inputs
                    .push(compressed.counters_disclosure_hash);
            }
        }
        Ok(PolicyRequest {
            body,
            indexed,
            reads: self.reads,
            approval_required: self.approval_required,
            circuit: self.circuit,
            transaction_salt: self
                .compressed
                .map(|compressed| compressed.transaction_salt),
        })
    }
}

pub(crate) struct PolicyRequest {
    pub body: crate::request::PolicyBody,
    pub indexed: Option<IndexedPolicyData>,
    pub reads: PolicyReads,
    pub approval_required: bool,
    pub circuit: RingCircuit,
    pub transaction_salt: Option<[u8; 16]>,
}

impl PolicyRequest {
    fn envelope(&self) -> PolicyEnvelope<'_> {
        PolicyEnvelope {
            transaction_salt: self.transaction_salt,
            circuit_type: self.circuit,
            policy: &self.body,
        }
    }

    /// The prover's request body, the plain policy circuit takes the body unwrapped.
    pub(crate) fn request(
        &self,
    ) -> Result<zolana_client::prover::requests::CircuitRequest, ClientError> {
        match self.circuit {
            RingCircuit::Policy => requests::CircuitRequest::of(&RingRequest(&self.body)),
            _ => requests::CircuitRequest::of(&RingRequest(&self.envelope())),
        }
    }

    async fn prove<P: AsyncRpc, I: AsyncIndexer>(
        mut self,
        client: &AsyncZolanaClient<P, I>,
    ) -> Result<(Proof, PolicyReads), RingError> {
        let request = self.request()?;
        let Some((prover, data)) = client.indexed_prover().zip(self.indexed.take()) else {
            return Ok((client.prove_request(&request).await?, self.reads));
        };
        let indexed = IndexedPolicyRequest::new(request.body()?, request.proving_key()?, data)?;
        let proof = prover.prove_indexed(&indexed).await?;
        // The resolved roots enter the transaction only after the statement verifies.
        self.circuit
            .verify(&proof.proof, proof.resolution.public_input_hash)?;
        self.reads.trees = proof
            .resolution
            .trees
            .into_iter()
            .map(|tree| PolicyTreeContext {
                tree: tree.tree,
                context: tree.context,
            })
            .collect();
        Ok((proof.proof, self.reads))
    }
}

enum Tier {
    Base(Box<BaseBody>),
    Policy(Box<PolicyRequest>),
}

impl Tier {
    async fn prove<P: AsyncRpc, I: AsyncIndexer>(
        self,
        client: &AsyncZolanaClient<P, I>,
    ) -> Result<(Proof, Option<PolicyReads>, bool), RingError> {
        match self {
            Self::Base(body) => Ok((
                client.prove_request(&RingRequest(&*body)).await?,
                None,
                false,
            )),
            Self::Policy(request) => {
                let approval_required = request.approval_required;
                let (proof, reads) = boxed(|| request.prove(client)).await?;
                Ok((proof, Some(reads), approval_required))
            }
        }
    }
}

/// The SPP half, complete with fetched proofs or prepared for the prover to fetch them.
enum Spp {
    Complete(Box<CompleteSpp>),
    Indexed(Box<PreparedIndexedTransfer>),
}

struct CompleteSpp {
    inputs: TransferInputs,
    nullifiers: Vec<[u8; 32]>,
    input_tree_indexes: Vec<u8>,
    tree_contexts: Vec<TreeContext>,
    private_tx_hash: [u8; 32],
    authority: bool,
}

impl Spp {
    async fn witness<R: Rail, P: AsyncRpc, I: AsyncIndexer>(
        transfer: &RingTransfer<R>,
        client: &AsyncZolanaClient<P, I>,
        staged: &Staged,
        trees: &SpendTrees,
    ) -> Result<Self, RingError> {
        let inputs = &staged.proof_inputs;
        let program = transfer.ring.program_id();
        let authority = staged.delegate.is_some();
        if client.indexed_prover().is_some() {
            let rail = match authority {
                true => IndexedTransferRail::RingAuthority(program),
                false => IndexedTransferRail::Ring(program),
            };
            let prepared = IndexedTransferPreparation {
                transaction: inputs.clone(),
                rail,
            }
            .prepare_with_dummy_policy(&staged.authority, trees.allow_dummy_inputs)?;
            return Ok(Self::Indexed(Box::new(prepared)));
        }
        let commitments = inputs.input_utxo_hashes()?;
        let witnesses = AsyncWitnessReader::input_witnesses(
            client.indexer(),
            &commitments,
            &inputs.dummy_nullifiers(),
            None,
        )
        .await?;
        let spends = attach_input_proofs(
            inputs.input_utxos.clone(),
            &witnesses.spend_proofs,
            &witnesses.dummy_nullifier_proofs,
        )?;
        let shape = inputs.check_shape()?;
        let mut complete = match authority {
            false => {
                let result = RingTransferProver {
                    inputs: spends,
                    outputs: inputs.output_utxos.clone(),
                    blinding_seed: inputs.blinding_seed,
                    output_tree_id: inputs.output_tree_id,
                    external_data: inputs.external_data.clone(),
                    public_transfers: inputs.public_transfers()?,
                    signer_pk_hashes: inputs.signer_pk_hashes(shape.signer_width())?,
                    allow_dummy_inputs: trees.allow_dummy_inputs,
                    ring_program_id: Some(program),
                    shape,
                }
                .build()?;
                CompleteSpp {
                    inputs: result.inputs,
                    nullifiers: result.nullifiers,
                    input_tree_indexes: result.input_tree_indexes,
                    tree_contexts: result.tree_contexts,
                    private_tx_hash: result.private_tx_hash,
                    authority,
                }
            }
            true => {
                let result = RingAuthorityProver {
                    inputs: spends,
                    outputs: inputs.output_utxos.clone(),
                    blinding_seed: inputs.blinding_seed,
                    output_tree_id: inputs.output_tree_id,
                    external_data: inputs.external_data.clone(),
                    public_transfers: inputs.public_transfers()?,
                    payer: inputs.payer,
                    allow_dummy_inputs: trees.allow_dummy_inputs,
                    ring_program_id: Some(program),
                    shape,
                }
                .build()?;
                CompleteSpp {
                    inputs: result.inputs,
                    nullifiers: result.nullifiers,
                    input_tree_indexes: result.input_tree_indexes,
                    tree_contexts: result.tree_contexts,
                    private_tx_hash: result.private_tx_hash,
                    authority,
                }
            }
        };
        staged
            .authority
            .complete_inputs(&mut complete.inputs.inputs)?;
        Ok(Self::Complete(Box::new(complete)))
    }

    fn private_tx_hash(&self) -> [u8; 32] {
        match self {
            Self::Complete(complete) => complete.private_tx_hash,
            Self::Indexed(prepared) => prepared.private_tx_hash(),
        }
    }

    async fn prove<P: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<P, I>,
        transaction: &SppProofInputs,
    ) -> Result<(TransactIxData, Vec<SppProofOutputUtxo>), RingError> {
        let outputs = transaction.output_utxos.clone();
        let complete = match self {
            Self::Indexed(prepared) => {
                let prover = client
                    .indexed_prover()
                    .ok_or(ClientError::InvalidIndexedRequest)?;
                return Ok((prover.prove_indexed(prepared.as_ref()).await?.data, outputs));
            }
            Self::Complete(complete) => complete,
        };
        let request = match complete.authority {
            true => requests::ring_authority(&complete.inputs)?,
            false => requests::transfer_ring(&complete.inputs)?,
        };
        let proof = client.prove_request(&request).await?;
        let shape = transaction.check_shape()?;
        let width = (
            shape.n_inputs() as u8,
            shape.n_outputs() as u8,
            N_PUBLIC_SLOTS as u8,
        );
        let circuit = match complete.authority {
            true => CircuitId::RingAuthority(width.0, width.1, width.2),
            false => CircuitId::RingEddsa(width.0, width.1, width.2),
        };
        let inputs =
            input_utxos_from_nullifiers(&complete.nullifiers, &complete.input_tree_indexes)?;
        if inputs.len() != usize::from(circuit.num_inputs()) {
            return Err(RingError::IncompleteProofSet);
        }
        let external = &transaction.external_data;
        let data = TransactIxData {
            proof: ProofCompressed::try_from(proof)?.to_transact_proof(),
            expiry_unix_ts: external.expiry_unix_ts,
            private_tx_hash: complete.private_tx_hash,
            circuit,
            inputs,
            tree_contexts: complete.tree_contexts.clone(),
            interface_transfers: external
                .interface_transfers
                .iter()
                .map(|transfer| transfer.interface_transfer())
                .collect(),
            data_hash: external.data_hash,
            ring_data_hash: external.ring_data_hash,
            tx_viewing_pk: external.tx_viewing_pk,
            salt: external.salt,
            outputs: external.outputs.clone(),
            messages: external.messages.clone(),
        };
        Ok((data, outputs))
    }
}

impl ProvenRingTransfer {
    pub(crate) fn bound_root(&self) -> Option<BoundRoot> {
        BoundRoot::of(self.ring, self.policy.as_ref()?.escrow)
    }

    pub fn instruction(&self) -> Result<Instruction, RingError> {
        match self.delegate {
            None => CustomRingTransact {
                ring: self.ring,
                payer: self.payer,
                input_trees: self.trees.inputs.clone(),
                output_tree: self.trees.output,
                policy: self.policy.clone(),
                cosigner: self.cosigner,
                owner_signers: self.owner_signers.clone(),
                interface_transfer_accounts: self.interface_transfer_accounts.clone(),
                proof: self.proof,
                transact: self.data.clone(),
                approval_required: self.approval_required,
                window_index: self.window_index,
            }
            .instruction(),
            Some(delegate) => CustomRingDelegateTransact {
                ring: self.ring,
                payer: self.payer,
                input_trees: self.trees.inputs.clone(),
                output_tree: self.trees.output,
                policy: self.policy.clone().ok_or(RingError::MissingPolicyConfig)?,
                cosigner: self.cosigner,
                delegate,
                proof: self.proof,
                transact: self.data.clone(),
                approval_required: self.approval_required,
            }
            .instruction(),
        }
    }
}

#[cfg(test)]
#[path = "../tests/pipeline.rs"]
mod tests;
