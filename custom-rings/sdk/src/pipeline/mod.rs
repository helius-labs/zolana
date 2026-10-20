//! One transfer pipeline for every rail. The owner signs its spends, the hidden owner of an
//! anonymous ring signs inside its proof, the delegate moves notes with the recovered key.

mod anonymous;
mod delegate;
mod owner;

use custom_ring_interface::ANONYMOUS_RING_SHAPES;
use solana_address::Address;
use solana_instruction::Instruction;
use zolana_client::{
    attach_input_proofs, input_utxos_from_nullifiers,
    prover::transact::{AnonymousEddsaTransferInputs, AnonymousRingEddsaProver},
    prover::{
        indexed::{
            IndexedPolicyData, IndexedPolicyRequest, IndexedTransferPreparation,
            IndexedTransferRail, PreparedIndexedTransfer,
        },
        requests,
    },
    AsyncIndexer, AsyncRpc, AsyncWitnessReader, AsyncZolanaClient, ClientError, Proof,
    ProofAuthority, ProofCompressed, ProveRequest, RingAuthorityProver, RingTransferProver,
    TransferInput, TransferInputs,
};
use zolana_interface::{
    instruction::{instruction_data::transact::TreeContext, CircuitId, TransactIxData},
    verifying_keys::{AnonymousRingEddsaProofData, Bsb22Commitment},
    N_PUBLIC_SLOTS,
};
use zolana_keypair::{NullifierKey, ViewingKey};
use zolana_transaction::{
    instructions::transact::{SppProofInputs, SppProofOutputUtxo},
    utxo::SppProofInputUtxo,
};

pub use self::{
    anonymous::{Anonymous, AnonymousRecipient, AnonymousTransfer},
    delegate::{ring_authority_width, DelegateOutput, DelegateTransferInput, Delegated},
    owner::{CustomRingTransferInput, Owner},
};
pub(crate) use owner::frame_dummy_outputs;

use crate::{
    audit::{PendingCustomRingProof, PolicyProof},
    heap::boxed,
    projection::retry_projection_lag,
    prover::{RingCircuit, RingRequest},
    request::{BaseBody, PolicyEnvelope},
    submission::BoundRoot,
    to_instruction_proof,
    trees::{spend_trees, SpendTrees},
    witness::WitnessInput,
    CustomRing, CustomRingDelegateTransact, CustomRingProof, CustomRingTransact,
    OutflowLimitProofInput, PinnedPolicy, PolicyReads, PolicyTreeContext, RingError, RingIdentity,
};
use zolana_program::instruction::TransactInterfaceTransferAccounts;

mod sealed {
    pub trait Sealed {}
}

/// Who authorizes the spends, the owner, the hidden owner or the delegate with the recovered key.
pub trait Rail: sealed::Sealed + Send + Sync {
    #[doc(hidden)]
    fn kind(&self) -> RailKind<'_>;
}

#[doc(hidden)]
pub enum RailKind<'a> {
    Owner(&'a Owner<'a>),
    Anonymous(&'a Anonymous<'a>),
    Delegated(&'a Delegated<'a>),
}

#[must_use = "prove or discard the transfer explicitly"]
pub struct RingTransfer<R: Rail> {
    ring: CustomRing,
    rail: R,
    cosigner: Option<Address>,
}

pub type CustomRingTransfer<'a> = RingTransfer<Owner<'a>>;
pub type DelegateTransfer<'a> = RingTransfer<Delegated<'a>>;

#[must_use = "build or submit the proven transfer"]
pub struct ProvenRingTransfer {
    policy_kind: custom_ring_interface::PolicyProofKind,
    pub tx_viewing_key: ViewingKey,
    pub data: TransactIxData,
    pub proof: CustomRingProof,
    /// `None` on an audit-only ring.
    pub policy: Option<PolicyReads>,
    pub cosigner: Option<Address>,
    /// The outflow limits demand the co-signer, the caller signs with it.
    pub approval_required: bool,
    /// Padding included.
    pub outputs: Vec<SppProofOutputUtxo>,
    /// The eddsa owners of the spent UTXOs, empty on the delegate and anonymous rails.
    pub owner_signers: Vec<Address>,
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
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
    /// `None` commits the pinned limits without bounding the transfer.
    pub limits: Option<OutflowLimitProofInput>,
    pub authority: TransferAuthority,
    /// Every live output owner's record must escrow the key the output uses.
    pub key_escrow: bool,
    pub owner_signers: Vec<Address>,
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    pub delegate: Option<Address>,
}

/// `None` only for an all-padding transfer, which completes no input.
pub(crate) struct TransferAuthority {
    pub owner: Option<NullifierKey>,
}

impl ProofAuthority for TransferAuthority {
    fn complete_inputs(&self, inputs: &mut [TransferInput]) -> Result<(), ClientError> {
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
            RailKind::Anonymous(rail) => {
                boxed(|| rail.stage(self.ring, client, &config, self.cosigner)).await?
            }
            RailKind::Delegated(delegated) => {
                boxed(|| delegated.stage(self.ring, client, &config)).await?
            }
        };
        check_distinct(&staged.proof_inputs.input_utxos)?;
        let inputs = &staged.proof_inputs;
        // A missing or foreign tree fails before the indexer serves proofs against it.
        let trees = spend_trees(client, &inputs.input_utxos, inputs.output_tree_id).await?;
        let indexed = client.indexed_prover().is_some();
        let spp = Spp::witness(self, client, &staged, &trees, indexed).await?;
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
        let preview = ProvenRingTransfer {
            policy_kind: custom_ring_interface::PolicyProofKind::Base,
            tx_viewing_key: staged.tx_viewing_key.clone(),
            data: spp.preview(inputs)?,
            proof: CustomRingProof {
                groth16: custom_ring_interface::PlainGroth16Proof {
                    proof_a: [0; 32],
                    proof_b: [0; 64],
                    proof_c: [0; 32],
                },
                commitment: [0; 32],
                commitment_pok: [0; 32],
            },
            policy: policy.as_ref().map(|policy| policy.reads.clone()),
            cosigner: self.cosigner,
            approval_required: policy
                .as_ref()
                .is_some_and(|policy| policy.approval_required),
            outputs: Vec::new(),
            owner_signers: staged.owner_signers.clone(),
            interface_transfer_accounts: staged.interface_transfer_accounts.clone(),
            payer: inputs.payer,
            delegate: staged.delegate,
            trees: trees.clone(),
            ring: self.ring,
        };
        crate::submission::check_transaction_size(&inputs.payer, &preview.instruction()?)?;
        let private_tx_hash = spp.private_tx_hash();
        let tier = match policy {
            Some(policy) => Tier::Policy(Box::new(policy.finish(staged.pending, private_tx_hash)?)),
            None => Tier::Base(Box::new(match staged.pending.is_anonymous() {
                true => staged
                    .pending
                    .finish_anonymous_base(private_tx_hash, &staged.proof_inputs)?,
                false => staged.pending.finish_base(private_tx_hash)?,
            })),
        };
        // Neither proof is an input to the other, the requests go out together.
        let ((data, outputs), (proof, policy, approval_required, policy_kind)) = futures::try_join!(
            boxed(|| spp.prove(client, &staged.proof_inputs)),
            boxed(|| tier.prove(client)),
        )?;
        Ok(ProvenRingTransfer {
            policy_kind,
            tx_viewing_key: staged.tx_viewing_key,
            data,
            proof: to_instruction_proof(proof)?,
            policy,
            cosigner: self.cosigner,
            approval_required,
            outputs,
            owner_signers: staged.owner_signers,
            interface_transfer_accounts: staged.interface_transfer_accounts,
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
        let shape = inputs.check_shape()?;
        if !custom_ring_interface::policy_shape_supported(
            shape.n_inputs(),
            shape.n_outputs(),
            staged.pending.is_anonymous(),
            staged.delegate.is_some(),
        ) {
            return Err(RingError::PolicyShapeUnsupported);
        }
        let limits = match staged.limits {
            Some(limits) => limits,
            None => committed(self.ring, pinned)?,
        };
        let witness = WitnessInput {
            ring: self.ring,
            pinned,
            inputs: &inputs.input_utxos,
            outputs: &inputs.output_utxos,
            output_tree_id: inputs.output_tree_id,
            private_tx_blinding: inputs.private_tx_blinding()?,
            limits,
            key_escrow: staged.key_escrow,
        }
        .build(client, indexed)
        .await?;
        let circuit = match staged.delegate {
            Some(_) => RingCircuit::DelegatePolicy,
            None => RingCircuit::Policy,
        };
        Ok(PolicyStatement {
            approval_required: witness.limits.approval_required,
            reads: witness.reads(),
            witness,
            policy_hash: pinned.config.policy_hash,
            circuit,
            shape: zolana_interface::shape::Shape::new(
                inputs.input_utxos.len(),
                inputs.output_utxos.len(),
            ),
            published_inputs: inputs
                .input_utxos
                .iter()
                .filter(|input| !input.is_compact())
                .count(),
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

/// The delegate rail commits the pinned limits without bounding its move.
fn committed(ring: CustomRing, pinned: &PinnedPolicy) -> Result<OutflowLimitProofInput, RingError> {
    let limits = pinned.table.limits();
    let mut input =
        OutflowLimitProofInput::none(RingIdentity::new(ring, pinned.config.namespace_owner_hash)?);
    input.limit_count = limits.len() as u8;
    input.limits[..limits.len()].copy_from_slice(limits);
    Ok(input)
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
    shape: zolana_interface::shape::Shape,
    published_inputs: usize,
}

impl PolicyStatement {
    fn finish(
        self,
        pending: PendingCustomRingProof,
        private_tx_hash: [u8; 32],
    ) -> Result<PolicyRequest, RingError> {
        let PolicyProof { mut body, indexed } =
            pending.finish(private_tx_hash, self.witness, &self.policy_hash)?;
        let circuit = if indexed.is_none()
            && self.published_inputs == 2
            && body.witness.supports_two_by_three()
        {
            match (self.circuit, body.anonymous.is_some()) {
                (RingCircuit::DelegatePolicy, _) => RingCircuit::DelegatePolicyTwoByThree,
                (_, true) => RingCircuit::AnonymousPolicyTwoByThree,
                (_, false) => RingCircuit::PolicyTwoByThree,
            }
        } else {
            let delegate = self.circuit == RingCircuit::DelegatePolicy;
            let anonymous = body.anonymous.is_some();
            let supported = if delegate {
                self.shape.is_ring_authority()
            } else if anonymous {
                ANONYMOUS_RING_SHAPES.contains(&self.shape)
            } else {
                self.shape.is_supported()
            };
            if !supported {
                return Err(RingError::PolicyShapeUnsupported);
            }
            let subtree = indexed.is_none() && body.witness.shared_subtree();
            body.witness
                .reshape(self.shape.n_inputs(), self.shape.n_outputs())?;
            RingCircuit::Shaped {
                inputs: self.shape.n_inputs() as u8,
                outputs: self.shape.n_outputs() as u8,
                anonymous,
                delegate,
                subtree,
            }
        };
        let public_table = if circuit.proof_kind().public_table() {
            body.circuit_type = circuit;
            Some(
                body.witness
                    .public_table_inputs(body.public_input_hash, self.policy_hash)?,
            )
        } else {
            None
        };
        Ok(PolicyRequest {
            public_table,
            body,
            indexed,
            reads: self.reads,
            approval_required: self.approval_required,
            circuit,
        })
    }
}

pub(crate) struct PolicyRequest {
    pub public_table: Option<Box<custom_ring_interface::PolicyTableInputs>>,
    pub body: crate::request::PolicyBody,
    pub indexed: Option<IndexedPolicyData>,
    pub reads: PolicyReads,
    pub approval_required: bool,
    pub circuit: RingCircuit,
}

impl PolicyRequest {
    fn envelope(&self) -> PolicyEnvelope<'_> {
        PolicyEnvelope {
            circuit_type: self.circuit,
            policy: &self.body,
        }
    }

    /// The prover's request body, the member circuit takes the body unwrapped.
    pub(crate) fn request(
        &self,
    ) -> Result<zolana_client::prover::requests::CircuitRequest, ClientError> {
        match self.circuit {
            RingCircuit::Policy
            | RingCircuit::PolicyTwoByThree
            | RingCircuit::AnonymousPolicyTwoByThree
            | RingCircuit::Shaped {
                delegate: false, ..
            } => requests::CircuitRequest::of(&RingRequest(&self.body)),
            _ => requests::CircuitRequest::of(&RingRequest(&self.envelope())),
        }
    }

    async fn prove<P: AsyncRpc, I: AsyncIndexer>(
        mut self,
        client: &AsyncZolanaClient<P, I>,
    ) -> Result<(Proof, PolicyReads), RingError> {
        let request = self.request()?;
        let Some((prover, data)) = client.indexed_prover().zip(self.indexed.take()) else {
            let proof = client.prove_request(&request).await?;
            if let Some(inputs) = &self.public_table {
                self.circuit.verify_table(&proof, inputs)?;
            }
            return Ok((proof, self.reads));
        };
        let indexed = IndexedPolicyRequest::new(request.body()?, request.proving_key()?, data)?;
        let proof = prover.prove_indexed(&indexed).await?;
        // The resolved roots enter the transaction only after the statement verifies.
        if let Some(inputs) = &self.public_table {
            // Indexed policy resolution must reproduce the pinned trees and statement.
            if inputs[0] != proof.resolution.public_input_hash {
                return Err(RingError::Client(ClientError::ProofVerification(
                    "resolved policy statement differs".to_owned(),
                )));
            }
            self.circuit.verify_table(&proof.proof, inputs)?;
        } else {
            self.circuit
                .verify(&proof.proof, proof.resolution.public_input_hash)?;
        }
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
    ) -> Result<
        (
            Proof,
            Option<PolicyReads>,
            bool,
            custom_ring_interface::PolicyProofKind,
        ),
        RingError,
    > {
        match self {
            Self::Base(body) => Ok((
                client.prove_request(&RingRequest(&*body)).await?,
                None,
                false,
                custom_ring_interface::PolicyProofKind::Base,
            )),
            Self::Policy(request) => {
                let approval_required = request.approval_required;
                let policy_kind = request.circuit.proof_kind();
                let (proof, reads) = boxed(|| request.prove(client)).await?;
                Ok((proof, Some(reads), approval_required, policy_kind))
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
    inputs: SppInputs,
    nullifiers: Vec<[u8; 32]>,
    input_tree_indexes: Vec<u8>,
    tree_contexts: Vec<TreeContext>,
    private_tx_hash: [u8; 32],
}

enum SppInputs {
    Ring(TransferInputs),
    Authority(TransferInputs),
    /// The hidden owner's key, signature and signed digest ride along.
    Anonymous {
        inputs: Box<AnonymousEddsaTransferInputs>,
        default_owner_tag: Option<[u8; 32]>,
    },
}

impl SppInputs {
    fn transfer(&mut self) -> &mut TransferInputs {
        match self {
            Self::Ring(inputs) | Self::Authority(inputs) => inputs,
            Self::Anonymous { inputs, .. } => &mut inputs.transfer,
        }
    }
}

impl Spp {
    async fn witness<R: Rail, P: AsyncRpc, I: AsyncIndexer>(
        transfer: &RingTransfer<R>,
        client: &AsyncZolanaClient<P, I>,
        staged: &Staged,
        trees: &SpendTrees,
        indexed: bool,
    ) -> Result<Self, RingError> {
        let inputs = &staged.proof_inputs;
        let program = transfer.ring.program_id();
        let authority = staged.delegate.is_some();
        let hidden = match transfer.rail.kind() {
            RailKind::Anonymous(rail) => Some(rail.signer),
            RailKind::Owner(_) | RailKind::Delegated(_) => None,
        };
        if indexed {
            let rail = match (authority, hidden) {
                (false, Some(owner)) => IndexedTransferRail::AnonymousRingEddsa {
                    ring: program,
                    owner,
                },
                (true, _) => IndexedTransferRail::RingAuthority(program),
                (false, None) => IndexedTransferRail::Ring(program),
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
        let mut complete = match (authority, hidden) {
            (false, Some(owner)) => {
                let result = AnonymousRingEddsaProver {
                    inputs: spends,
                    outputs: inputs.output_utxos.clone(),
                    blinding_seed: inputs.blinding_seed,
                    output_tree_id: inputs.output_tree_id,
                    external_data: inputs.external_data.clone(),
                    public_transfers: inputs.public_transfers()?,
                    signer_pk_hashes: anonymous::anonymous_signers(shape.signer_width()),
                    allow_dummy_inputs: trees.allow_dummy_inputs,
                    owner,
                    ring_program_id: Some(program),
                    shape,
                }
                .build()?;
                CompleteSpp {
                    inputs: SppInputs::Anonymous {
                        inputs: Box::new(result.inputs),
                        default_owner_tag: result.default_owner_tag,
                    },
                    nullifiers: result.nullifiers,
                    input_tree_indexes: result.input_tree_indexes,
                    tree_contexts: result.tree_contexts,
                    private_tx_hash: result.private_tx_hash,
                }
            }
            (false, None) => {
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
                    inputs: SppInputs::Ring(result.inputs),
                    nullifiers: result.nullifiers,
                    input_tree_indexes: result.input_tree_indexes,
                    tree_contexts: result.tree_contexts,
                    private_tx_hash: result.private_tx_hash,
                }
            }
            (true, _) => {
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
                    inputs: SppInputs::Authority(result.inputs),
                    nullifiers: result.nullifiers,
                    input_tree_indexes: result.input_tree_indexes,
                    tree_contexts: result.tree_contexts,
                    private_tx_hash: result.private_tx_hash,
                }
            }
        };
        staged
            .authority
            .complete_inputs(&mut complete.inputs.transfer().inputs)?;
        Ok(Self::Complete(Box::new(complete)))
    }

    fn private_tx_hash(&self) -> [u8; 32] {
        match self {
            Self::Complete(complete) => complete.private_tx_hash,
            Self::Indexed(prepared) => prepared.private_tx_hash(),
        }
    }

    fn preview(&self, transaction: &SppProofInputs) -> Result<TransactIxData, RingError> {
        let complete = match self {
            Self::Indexed(prepared) => return Ok(prepared.transaction_template().clone()),
            Self::Complete(complete) => complete,
        };
        let shape = transaction.check_shape()?;
        let (n, m, p) = (
            shape.n_inputs() as u8,
            shape.n_outputs() as u8,
            N_PUBLIC_SLOTS as u8,
        );
        let circuit = match complete.inputs {
            SppInputs::Ring(_) => CircuitId::ConfidentialRingEddsa(n, m, p),
            SppInputs::Authority(_) => CircuitId::RingAuthority(n, m, p),
            SppInputs::Anonymous {
                default_owner_tag, ..
            } => CircuitId::AnonymousRingEddsa(
                n,
                m,
                p,
                AnonymousRingEddsaProofData {
                    bsb22_commitment: Bsb22Commitment {
                        commitment: [0; 32],
                        commitment_pok: [0; 32],
                    },
                    default_owner_tag,
                },
            ),
        };
        let external = &transaction.external_data;
        Ok(TransactIxData {
            proof: zolana_interface::instruction::TransactProof::zeroed(),
            expiry_unix_ts: external.expiry_unix_ts,
            private_tx_hash: complete.private_tx_hash,
            circuit,
            inputs: input_utxos_from_nullifiers(
                &complete.nullifiers,
                &complete.input_tree_indexes,
            )?,
            tree_contexts: complete.tree_contexts.clone(),
            interface_transfers: external
                .interface_transfers
                .iter()
                .map(|leg| leg.interface_transfer())
                .collect(),
            data_hash: external.data_hash,
            ring_data_hash: external.ring_data_hash,
            tx_viewing_pk: external.tx_viewing_pk,
            salt: external.salt,
            outputs: external.outputs.clone(),
            messages: external.messages.clone(),
        })
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
        let proof = match &complete.inputs {
            SppInputs::Ring(inputs) => {
                client
                    .prove_request(&requests::transfer_ring(inputs)?)
                    .await?
            }
            SppInputs::Authority(inputs) => {
                client
                    .prove_request(&requests::ring_authority(inputs)?)
                    .await?
            }
            SppInputs::Anonymous { inputs, .. } => client.prove_request(inputs.as_ref()).await?,
        };
        let proof = ProofCompressed::try_from(proof)?;
        let shape = transaction.check_shape()?;
        let width = (
            shape.n_inputs() as u8,
            shape.n_outputs() as u8,
            N_PUBLIC_SLOTS as u8,
        );
        let (circuit, proof) = match &complete.inputs {
            SppInputs::Ring(_) => (
                CircuitId::ConfidentialRingEddsa(width.0, width.1, width.2),
                proof.to_transact_proof(),
            ),
            SppInputs::Authority(_) => (
                CircuitId::RingAuthority(width.0, width.1, width.2),
                proof.to_transact_proof(),
            ),
            // The selector carries the emulated-field commitment the verifier checks.
            SppInputs::Anonymous {
                default_owner_tag, ..
            } => {
                let (proof, bsb22_commitment) = proof.into_committed_transact_parts()?;
                (
                    CircuitId::AnonymousRingEddsa(
                        width.0,
                        width.1,
                        width.2,
                        AnonymousRingEddsaProofData {
                            bsb22_commitment,
                            default_owner_tag: *default_owner_tag,
                        },
                    ),
                    proof,
                )
            }
        };
        let inputs =
            input_utxos_from_nullifiers(&complete.nullifiers, &complete.input_tree_indexes)?;
        let published_inputs = transaction
            .input_utxos
            .iter()
            .filter(|input| !input.is_compact())
            .count();
        if complete.nullifiers.len() != usize::from(circuit.num_inputs())
            || inputs.len() != published_inputs
        {
            return Err(RingError::IncompleteProofSet);
        }
        let external = &transaction.external_data;
        let data = TransactIxData {
            proof,
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
        Some(BoundRoot::registry(
            self.ring,
            self.policy.as_ref()?.registry,
        ))
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
            }
            .instruction_with_policy_kind(self.policy_kind),
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
            .instruction_with_policy_kind(self.policy_kind),
        }
    }
}

#[cfg(test)]
#[path = "../tests/pipeline.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/privacy.rs"]
mod privacy;
