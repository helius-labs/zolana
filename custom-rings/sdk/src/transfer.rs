#[cfg(feature = "solana-rpc")]
use crate::instructions::transact::ProvedWindow;
use core::future::Future;

use custom_ring_interface::PolicyConfig;
use custom_ring_interface::{RingDepositAuditCapsule, MAX_RING_DEPOSIT_AUDIT_SLOTS};
use futures::future::try_join;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use solana_account::Account;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_signature::Signature;
use solana_signer::Signer;
use thiserror::Error;
use zeroize::Zeroizing;
use zolana_client::{
    input_utxos_from_nullifiers,
    prover::{Delivery, ProveRequest},
    AsyncProverClient, AsyncRpc, ClientError, ComputeBudgetConfig, MerkleProof, NonInclusionProof,
    Proof, ProofAuthority, ProofCompressed, ProofInputUtxo, ProverClient, RingTransferProofResult,
    RingTransferProver, Rpc, SettlementAccountValidation, SpendProof, TransferInputUtxo,
    TransferInputs,
};
use zolana_interface::event::OutputDataEncoding;
use zolana_interface::{
    instruction::{
        tag::RING_TRANSACT, CircuitId, DepositAsset, DepositBuildError, OwnerTag, RingAssetDeposit,
        TransactInterfaceTransferAccounts, TransactIxData, TransactOutput, TransactProof,
    },
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{
    random_blinding, KeypairError, NullifierKey, P256Pubkey, ShieldedAddress, ShieldedKeypair,
    ViewingKey,
};
use zolana_ring_client::{DepositOpening, DepositSeal};
use zolana_ring_policy::{ListNamespace, Member, VelocityMode, VelocityRow};
use zolana_transaction::{
    instructions::transact::{
        ConfidentialTransaction, ExternalData, ResolvedOwnerTag, SppProofInputs, SppProofOutputUtxo,
    },
    keys::{ShieldedKeys, TransactionKeyRequest},
    owner_utxo_hash,
    serialization::confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding, SppProofInputUtxo},
    Data, EncryptedScheme, Mint, RingDepositPlaintext, TransactionError, Utxo, UtxoSerialization,
};
use zolana_tree::{TreeAccount, TreeError};

use crate::{
    head_map::HeadWitness,
    instructions::{
        entry::zero_nullifier_key,
        spend::{ReadEnvironment, ReadSpendRecord},
        transact::{
            request::json_body, CustomRingPolicyProofRequestJson, HeadTransitionJson, RingIdentity,
            VelocityProofInput,
        },
    },
    to_instruction_proof,
    velocity::{
        ChargeRows, Outflows, VelocityContext, VelocityFacts, VelocityPlan, VelocityPlanInput,
    },
    witness::{list_entry, CustomRingWitness, CustomRingWitnessInput, TransactRoots},
    AccountReadError, CustomRing, CustomRingBaseProofRequest, CustomRingConfig,
    CustomRingPolicyProofRequest, CustomRingProof, CustomRingProofError, CustomRingProofInputError,
    CustomRingProofParams, CustomRingTransact, Deposit, EncryptedAudit, PendingCustomRingProof,
    PinnedPolicy, PolicyMatchError,
};

const NO_RING_DATA_HASH: [u8; 32] = [0u8; 32];

#[must_use = "prove or discard the transfer explicitly"]
#[derive(Clone)]
pub struct CustomRingTransfer<'a> {
    ring: CustomRing,
    sender: &'a (dyn ShieldedKeys + Send + Sync),
    nullifier_key: Option<&'a NullifierKey>,
    transaction: ConfidentialTransaction,
    interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    input_tree: Option<Address>,
    output_tree: Option<Address>,
    cosigner: Option<Address>,
}

pub struct CustomRingTransferInput<'a> {
    pub ring: CustomRing,
    /// The sender's key holder. Only [`ShieldedKeys::transaction_keys`] and
    /// [`ShieldedKeys::address`] are used, so a backend that keeps the owner's
    /// signing key elsewhere -- an HSM, or a remote custodian -- can build a
    /// transfer. The owner's signature is not taken here: [`ProvenTransfer`]
    /// reports `owner_signers`, and the owner signs the assembled Solana
    /// transaction.
    ///
    /// `ShieldedKeypair` and `LocalShieldedKeys` both implement the trait, so a
    /// software wallet passes one of those.
    ///
    /// `Send + Sync` so that [`Self::prove_async`]'s future is `Send`. Without
    /// it the async path cannot be awaited on a multi-threaded runtime, which
    /// is exactly where a host that needs the async path runs.
    pub sender: &'a (dyn ShieldedKeys + Send + Sync),
    /// The spend secret for the inputs this caller owns, acting as their
    /// [`ProofAuthority`]: the assembled witness leaves every real input's
    /// secret absent and this completes the ones it owns. The circuit consumes
    /// the raw secret rather than deriving it, so proving a real input without
    /// one fails. `None` is only valid for an all-padding transfer.
    pub nullifier_key: Option<&'a NullifierKey>,
    /// The transaction with its output slots already padded to its shape.
    pub transaction: ConfidentialTransaction,
}

pub struct TransferProofEnvironment<'a, I: Rpc, R: Rpc> {
    pub indexer: &'a I,
    pub rpc: &'a R,
    pub prover: &'a ProverClient,
}

/// The async counterpart of [`TransferProofEnvironment`].
pub struct AsyncTransferProofEnvironment<'a, I: AsyncRpc, R: AsyncRpc> {
    pub indexer: &'a I,
    pub rpc: &'a R,
    pub prover: &'a AsyncProverClient,
}

#[must_use = "build or submit the proven transfer"]
pub struct ProvenTransfer {
    pub tx_viewing_key: ViewingKey,
    pub data: TransactIxData,
    pub proof: CustomRingProof,
    pub owner_signers: Vec<Address>,
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    /// History entries a policy statement binds, zero without rules.
    pub state_root_index: u16,
    pub nullifier_root_index: u16,
    pub revocation_targets: [[u8; 32]; zolana_ring_policy::ANSWER_SLOTS],
    pub cosigner: Option<Address>,
    /// The velocity statement demands the co-signer, the caller must sign with it.
    pub approval_required: bool,
    pub head_transition: Option<custom_ring_interface::HeadMapTransition>,
    #[cfg(feature = "solana-rpc")]
    pub(crate) window: Option<ProvedWindow>,
    payer: Address,
    input_tree: Address,
    output_tree: Address,
    /// The pinned entries tree for a policy ring, `None` for an audit-only ring.
    entries_tree: Option<Address>,
    /// Present only for windowed member transfers.
    head_map_root: Option<Address>,
    ring: CustomRing,
}

#[must_use]
pub struct RingDeposit<'a> {
    pub ring: CustomRing,
    /// Lamport source for Sol, the user token's authority for Spl.
    pub payer: &'a dyn Signer,
    pub recipient: &'a ShieldedKeypair,
    pub tree: Address,
    pub asset: DepositAsset,
    pub amount: u64,
    /// The ring's co-signer when its scope covers deposits.
    pub cosigner: Option<&'a dyn Signer>,
}

pub struct RingDepositReceipt {
    pub signature: Signature,
    pub utxo: Utxo,
}

/// RPC and prover handles for deposits that require auditor disclosure.
pub struct DepositProofEnvironment<'a, R: Rpc> {
    pub rpc: &'a R,
    pub prover: &'a ProverClient,
}

#[derive(Debug, Error)]
pub enum TransferError {
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error(transparent)]
    ProofInput(#[from] CustomRingProofInputError),
    #[error(transparent)]
    Proof(#[from] CustomRingProofError),
    #[error(transparent)]
    Instruction(#[from] wincode::Error),
    #[error(transparent)]
    DelegateInstruction(#[from] crate::DelegateInstructionError),
    #[error(transparent)]
    Encoding(#[from] std::io::Error),
    #[error("indexer returned an incomplete proof set")]
    IncompleteProofSet,
    #[error("prover returned an incomplete input set")]
    IncompleteInputSet,
    #[error("input tree account does not exist")]
    MissingTree,
    #[error("input tree owner is invalid")]
    InvalidTreeOwner,
    #[error("input tree discriminator is invalid")]
    InvalidTreeDiscriminator,
    #[error("input tree address is required")]
    TreeRequired,
    #[error("tree {tree} has id {expected}, the transfer was prepared for {found}")]
    TreeIdMismatch {
        tree: Address,
        expected: u16,
        found: u16,
    },
    #[error("custom ring config does not exist")]
    MissingRingConfig,
    #[error("the ring has no policy config")]
    MissingPolicyConfig,
    #[error(transparent)]
    PolicyMatch(Box<PolicyMatchError>),
    #[error("policy hashing failed")]
    PolicyHashing,
    #[error("the transfer needs more policy slots than the circuit holds")]
    PolicyShapeUnsupported,
    #[error("a policy rule refuses the transfer")]
    PolicyRuleUnsatisfied,
    #[error("the transfer uses an asset without a configured policy limit")]
    PolicyAssetUnsupported,
    #[error("the indexer proved the entries against more than one root")]
    PolicyRootMismatch,
    #[error("no policy source serves the list")]
    MissingSourceOwner,
    #[error(transparent)]
    ListEntry(Box<crate::EntryProofError>),
    #[error("asset registry is required")]
    MissingAssetRegistry,
    #[error("dummy output framing is invalid")]
    InvalidDummyOutput,
    #[error(transparent)]
    Tree(#[from] TreeError),
    #[error("transfer references another ring {0}")]
    ForeignRing(Address),
    #[error("a default-ring note carries ring data")]
    RingDataOutsideRing,
    #[error("the ring has no delegate")]
    MissingDelegate,
    #[error("the ring's delegate is {0}")]
    UnauthorizedDelegate(Address),
    #[error("inputs and outputs of {0} differ")]
    UnbalancedMove(Address),
    #[error("the sender has no spend record, register first")]
    SpendRecordMissing,
    #[error("the live record's counters are not recoverable from its transfer")]
    SpendCountersUnknown,
    #[error("the spend record is newer than the current window, refresh chain state")]
    SpendRecordFromFutureWindow,
    #[error("the window cap {cap} of {asset:?} would be exceeded at {spent}")]
    VelocityCapExceeded {
        asset: [u8; 32],
        cap: u64,
        spent: u64,
    },
    #[error("a velocity sum overflows")]
    VelocityOverflow,
    #[error("change of {asset:?} exceeds the mint's inputs")]
    VelocityChangeExceedsInflow { asset: [u8; 32] },
    #[error("a windowed transfer spends and lands in the entries tree {entries_tree}")]
    EntriesTreeRequired { entries_tree: Address },
    #[error("a head transition needs a windowed policy statement")]
    HeadWithoutWindow,
}

impl From<PolicyMatchError> for TransferError {
    fn from(error: PolicyMatchError) -> Self {
        Self::PolicyMatch(Box::new(error))
    }
}

#[derive(Debug, Error)]
pub enum DepositError {
    #[error(transparent)]
    Encryption(#[from] zolana_ring_client::AuditEncryptionError),
    #[error(transparent)]
    Proof(#[from] CustomRingProofError),
    #[error("deposit proof input hashing failed")]
    Hashing,
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Instruction(#[from] DepositBuildError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error("custom ring config does not exist")]
    MissingRingConfig,
}

impl<'a> CustomRingTransfer<'a> {
    pub fn new(input: CustomRingTransferInput<'a>) -> Self {
        Self {
            ring: input.ring,
            sender: input.sender,
            nullifier_key: input.nullifier_key,
            transaction: input.transaction,
            interface_transfer_accounts: Vec::new(),
            input_tree: None,
            output_tree: None,
            cosigner: None,
        }
    }

    #[must_use = "use the updated transfer"]
    pub fn with_cosigner(mut self, cosigner: Address) -> Self {
        self.cosigner = Some(cosigner);
        self
    }

    /// The tree the spent notes live in, and where outputs land unless
    /// [`Self::with_output_tree`] moves them.
    #[must_use = "use the updated transfer"]
    pub fn with_tree(mut self, tree: Address) -> Self {
        self.input_tree = Some(tree);
        self
    }

    /// Land the outputs in a tree other than the input tree.
    #[must_use = "use the updated transfer"]
    pub fn with_output_tree(mut self, tree: Address) -> Self {
        self.output_tree = Some(tree);
        self
    }

    #[must_use = "use the updated transfer"]
    pub fn with_interface_transfer_accounts(
        mut self,
        accounts: Vec<TransactInterfaceTransferAccounts>,
    ) -> Self {
        self.interface_transfer_accounts = accounts;
        self
    }

    /// Proves the transfer over a blocking transport.
    pub fn prove<I: Rpc, R: Rpc>(
        self,
        environment: TransferProofEnvironment<'_, I, R>,
    ) -> Result<ProvenTransfer, TransferError> {
        let config = self
            .ring
            .read_config(environment.rpc)?
            .ok_or(TransferError::MissingRingConfig)?;
        let policy = match self.policy_lookup(&config, environment.rpc)? {
            Some(lookup) => Some(lookup.read(ReadEnvironment {
                indexer: environment.indexer,
                rpc: environment.rpc,
            })?),
            None => None,
        };
        let staged = self.stage(
            config.auditor_pubkey,
            policy
                .as_ref()
                .map_or(&SpendLimit::Unbounded, |policy| &policy.limit),
        )?;
        // The tree is read and validated first. A tree that is absent, owned by
        // another program, or not a tree account at all fails here rather than
        // after the indexer has served a full inclusion and non-inclusion proof
        // set that nothing can use.
        let input_tree = read_tree_state(environment.rpc, staged.input_tree)?;
        let output_tree = read_tree_state(environment.rpc, staged.output_tree)?;
        staged.check_tree_ids(input_tree.tree.id, output_tree.tree.id)?;
        let spends = SpendSet {
            inputs: RingSpendInputs {
                indexer: environment.indexer,
                tree: staged.input_tree,
                input_utxos: &staged.proof_inputs.input_utxos,
            }
            .load()?,
            allow_dummy_inputs: input_tree.allows_dummy_inputs(&staged.proof_inputs.input_utxos),
        };
        let tier = match &policy {
            Some(policy) => staged
                .policy_tier(&policy.pinned)?
                .build(environment.indexer, environment.rpc)?,
            None => Tier::Base,
        };
        let witnessed = staged.witness(spends, tier)?;
        let spp_proof =
            ProofCompressed::try_from(environment.prover.prove_transfer_ring(witnessed.spp())?)?
                .to_transact_proof();
        let ring_proof = environment.prover.prove(&witnessed.request)?;
        witnessed.finish(spp_proof, ring_proof)
    }

    /// The async twin of [`Self::prove`], over [`AsyncRpc`] and
    /// [`AsyncProverClient`].
    ///
    /// The blocking path needs `zolana-client`'s `solana-rpc` feature for its
    /// only Solana `Rpc` implementation, which a host pinned below the versions
    /// that feature requires cannot link. Such a host already speaks `AsyncRpc`
    /// over its own transport, and the rest of this SDK is async-first, so the
    /// ring transfer being blocking-only was the outlier.
    ///
    /// Both paths run the same proof assembly; only the five reads differ, and
    /// this one asks for its two proofs together rather than one after the other.
    pub async fn prove_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        environment: AsyncTransferProofEnvironment<'_, I, R>,
    ) -> Result<ProvenTransfer, TransferError> {
        let config = self
            .ring
            .read_config_async(environment.rpc)
            .await?
            .ok_or(TransferError::MissingRingConfig)?;
        let policy = match self.policy_lookup_async(&config, environment.rpc).await? {
            Some(lookup) => Some(
                lookup
                    .read_async(ReadEnvironment {
                        indexer: environment.indexer,
                        rpc: environment.rpc,
                    })
                    .await?,
            ),
            None => None,
        };
        let staged = self.stage(
            config.auditor_pubkey,
            policy
                .as_ref()
                .map_or(&SpendLimit::Unbounded, |policy| &policy.limit),
        )?;
        // Same ordering reason as the blocking path: validate the tree before
        // asking the indexer for proofs against it.
        let input_tree = read_tree_state_async(environment.rpc, staged.input_tree).await?;
        let output_tree = read_tree_state_async(environment.rpc, staged.output_tree).await?;
        staged.check_tree_ids(input_tree.tree.id, output_tree.tree.id)?;
        let spends = SpendSet {
            inputs: RingSpendInputs {
                indexer: environment.indexer,
                tree: staged.input_tree,
                input_utxos: &staged.proof_inputs.input_utxos,
            }
            .load_async()
            .await?,
            allow_dummy_inputs: input_tree.allows_dummy_inputs(&staged.proof_inputs.input_utxos),
        };
        let tier = match &policy {
            Some(policy) => {
                staged
                    .policy_tier(&policy.pinned)?
                    .build_async(environment.indexer, environment.rpc)
                    .await?
            }
            None => Tier::Base,
        };
        let witnessed = staged.witness(spends, tier)?;
        // Both witnesses are complete, and neither proof is an input to the
        // other: SPP proves the transfer, the ring circuit proves the auditor
        // encryption over the `private_tx_hash` the SPP witness already fixed.
        // So both requests go out together instead of the second waiting on the
        // first's proof, which it never needed. Whether they then prove at once
        // is the prover's call -- its sync admission control bounds in-request
        // proving, and one gnark proof already spreads across every free core --
        // but that bound belongs there, not in a caller that cannot see the
        // fleet. The blocking path has no way to express this.
        let (spp, ring) = try_join(
            environment.prover.prove_transfer_ring(witnessed.spp()),
            environment.prover.prove(&witnessed.request),
        )
        .await?;
        witnessed.finish(ProofCompressed::try_from(spp)?.to_transact_proof(), ring)
    }

    /// `None` for an audit-only ring.
    fn policy_lookup<R: Rpc>(
        &self,
        config: &CustomRingConfig,
        rpc: &R,
    ) -> Result<Option<PolicyLookup<'_>>, TransferError> {
        if !config.has_policy {
            return Ok(None);
        }
        let pinned = self
            .ring
            .read_pinned_policy(rpc)?
            .ok_or(TransferError::MissingPolicyConfig)?;
        Ok(Some(PolicyLookup {
            limit: self.spend_limit(&pinned)?,
            pinned,
        }))
    }

    async fn policy_lookup_async<R: AsyncRpc>(
        &self,
        config: &CustomRingConfig,
        rpc: &R,
    ) -> Result<Option<PolicyLookup<'_>>, TransferError> {
        if !config.has_policy {
            return Ok(None);
        }
        let pinned = self
            .ring
            .read_pinned_policy_async(rpc)
            .await?
            .ok_or(TransferError::MissingPolicyConfig)?;
        Ok(Some(PolicyLookup {
            limit: self.spend_limit(&pinned)?,
            pinned,
        }))
    }

    fn spend_limit(&self, pinned: &PinnedPolicy) -> Result<SpendLimitLookup<'_>, TransferError> {
        let identity = RingIdentity::new(self.ring, pinned.config.namespace_owner_hash)?;
        match pinned.table.velocity_mode() {
            VelocityMode::Off => Ok(SpendLimit::Unbounded),
            VelocityMode::PerTransfer => Ok(SpendLimit::PerTransfer {
                rows: pinned.table.velocity().to_vec(),
                identity,
            }),
            VelocityMode::PerWindow { window_slots } => {
                let entries_tree = pinned.config.address_tree;
                if self.input_tree != Some(entries_tree)
                    || self.output_tree.unwrap_or(entries_tree) != entries_tree
                {
                    return Err(TransferError::EntriesTreeRequired { entries_tree });
                }
                Ok(SpendLimit::PerWindow(Box::new(VelocityLookup {
                    read: ReadSpendRecord {
                        ring: self.ring,
                        entries_tree,
                        entries_tree_id: pinned.config.address_tree_id(),
                        member: sender_member(&self.sender.address()?)?,
                    },
                    context: VelocityContext {
                        namespace: self.ring.namespace_pda(),
                        owner: ListNamespace {
                            owner_hash: pinned.config.namespace_owner_hash,
                        },
                        identity,
                        entries_tree_id: pinned.config.address_tree_id(),
                        window_slots,
                        rows: pinned.table.velocity().to_vec(),
                        sender: self.sender,
                    },
                })))
            }
        }
    }

    /// Record openings and auditor ciphertext must precede the shared transaction hash.
    fn stage(
        self,
        auditor_pk: P256Pubkey,
        limit: &SpendLimit<VelocityFacts>,
    ) -> Result<StagedTransfer, TransferError> {
        let input_tree = self.input_tree.ok_or(TransferError::TreeRequired)?;
        let output_tree = self.output_tree.unwrap_or(input_tree);
        let transaction = self.transaction;
        let program_id = self.ring.program_id();
        validate_transfer_accounts(&transaction, &self.interface_transfer_accounts)?;
        let payer = transaction.payer();
        let sender = self.sender.address()?;
        let keys = self.sender.transaction_keys(&[TransactionKeyRequest {
            viewing_pubkey: sender.viewing_pubkey,
            first_nullifier: *transaction.first_nullifier(),
        }])?;
        let got = keys.len();
        let tx_viewing_key = keys
            .into_iter()
            .next()
            .ok_or(TransactionError::IncompleteDerivation { got, want: 1 })?;
        let sender_tag = transaction.sender_owner_tag(&sender.signing_pubkey)?;
        let mut proof_inputs = transaction.encrypt_with_viewing_key(&sender, &tx_viewing_key)?;

        RingMembership {
            program_id,
            inputs: &proof_inputs.input_utxos,
            outputs: &proof_inputs.output_utxos,
        }
        .validate()?;

        let money_shape = proof_inputs.check_shape()?;
        let first_nullifier = proof_inputs.first_nullifier()?;
        let output_blinding_seed =
            derive_output_blinding_seed(&first_nullifier, &proof_inputs.blinding_seed)?;
        let salt = proof_inputs.external_data.salt;
        let stage = match limit {
            SpendLimit::Unbounded => VelocityStage {
                plan: None,
                proof_input: None,
                head: None,
            },
            SpendLimit::PerTransfer { rows, identity } => {
                let outflows = Outflows {
                    sender: sender_member(&sender)?,
                    ring: program_id,
                    inputs: &proof_inputs.input_utxos,
                    outputs: &proof_inputs.output_utxos,
                };
                let charges = ChargeRows {
                    rows,
                    outflows: &outflows,
                    previous: None,
                }
                .charge()?;
                VelocityStage {
                    plan: None,
                    proof_input: Some(VelocityProofInput::per_transfer(&charges, *identity)),
                    head: None,
                }
            }
            SpendLimit::PerWindow(facts) => {
                let facts: &VelocityFacts = facts;
                let plan = VelocityPlanInput {
                    facts,
                    outflows: Outflows {
                        sender: sender_member(&sender)?,
                        ring: program_id,
                        inputs: &proof_inputs.input_utxos,
                        outputs: &proof_inputs.output_utxos,
                    },
                    tx_viewing_key: &tx_viewing_key,
                    salt,
                    first_nullifier,
                    output_blinding_seed,
                    money_shape,
                }
                .plan()?;
                RecordSlots {
                    plan: &plan,
                    tx_viewing_key: &tx_viewing_key,
                    sender_tag,
                }
                .append(&mut proof_inputs)?;
                VelocityStage {
                    proof_input: Some(plan.proof_input),
                    head: Some(CompressedHead {
                        witness: facts.head.clone(),
                        transition: plan.head_transition,
                        transaction_salt: salt,
                        counters_disclosure_hash:
                            zolana_ring_policy::spend_counters_disclosure_hash(
                                &salt,
                                plan.counters_message
                                    .data
                                    .as_slice()
                                    .try_into()
                                    .map_err(|_| TransferError::SpendCountersUnknown)?,
                            )
                            .map_err(|_| TransferError::PolicyHashing)?,
                    }),
                    plan: Some(plan),
                }
            }
        };

        frame_dummy_outputs(
            &proof_inputs.output_utxos,
            &mut proof_inputs.external_data.outputs,
        )?;
        let mut messages = Vec::with_capacity(3);
        if let Some(plan) = stage.plan {
            messages.push(plan.record_message);
            messages.push(plan.counters_message);
        }
        let EncryptedAudit {
            pending: pending_proof,
            message: auditor_message,
        } = CustomRingProofParams {
            tx_viewing_key: tx_viewing_key.clone(),
            auditor_pk,
            salt,
            outputs: proof_inputs
                .output_utxos
                .iter()
                .map(|output| ProofInputUtxo::try_from((output, proof_inputs.output_tree_id)))
                .collect::<Result<Vec<_>, _>>()?,
        }
        .encrypt()?;
        messages.push(auditor_message.to_message_data(&auditor_pk));
        proof_inputs.external_data.messages = messages;
        // RING_TRANSACT is folded into external_data_hash and from there into
        // private_tx_hash, so it must be bound before anything hashes external data.
        proof_inputs.external_data.instruction_discriminator = RING_TRANSACT;

        let head_map_root = stage.head.is_some().then(|| self.ring.head_map_root_pda());
        Ok(StagedTransfer {
            head_witness: stage.head,
            tx_viewing_key,
            nullifier_key: self.nullifier_key.cloned(),
            pending_proof,
            proof_inputs,
            payer,
            input_tree,
            output_tree,
            program_id,
            interface_transfer_accounts: self.interface_transfer_accounts,
            ring: self.ring,
            cosigner: self.cosigner,
            velocity: stage.proof_input,
            head_map_root,
        })
    }
}

/// The identity SPP hashes the sender as, one list serves every owner curve.
fn sender_member(owner: &ShieldedAddress) -> Result<Member, TransferError> {
    let sender = owner
        .signing_pubkey
        .owner_proof_input_hash()
        .map_err(|_| TransferError::PolicyHashing)?;
    Member::owner_identity(&sender).map_err(|_| TransferError::PolicyHashing)
}

struct PolicyLookup<'a> {
    pinned: PinnedPolicy,
    limit: SpendLimitLookup<'a>,
}

struct ResolvedPolicy {
    pinned: PinnedPolicy,
    limit: SpendLimit<VelocityFacts>,
}

impl PolicyLookup<'_> {
    fn read<I: Rpc, R: Rpc>(
        self,
        env: ReadEnvironment<'_, I, R>,
    ) -> Result<ResolvedPolicy, TransferError> {
        Ok(ResolvedPolicy {
            pinned: self.pinned,
            limit: self.limit.read(env)?,
        })
    }

    async fn read_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        env: ReadEnvironment<'_, I, R>,
    ) -> Result<ResolvedPolicy, TransferError> {
        Ok(ResolvedPolicy {
            pinned: self.pinned,
            limit: self.limit.read_async(env).await?,
        })
    }
}

/// The per-transfer rows carry no record.
struct VelocityStage {
    plan: Option<VelocityPlan>,
    proof_input: Option<VelocityProofInput>,
    head: Option<CompressedHead>,
}

/// The window read is the one transport-bound step.
enum SpendLimit<W> {
    Unbounded,
    PerTransfer {
        rows: Vec<VelocityRow>,
        identity: RingIdentity,
    },
    PerWindow(Box<W>),
}

type SpendLimitLookup<'a> = SpendLimit<VelocityLookup<'a>>;

impl<W> SpendLimit<W> {
    fn map_window<V, E>(self, read: impl FnOnce(W) -> Result<V, E>) -> Result<SpendLimit<V>, E> {
        Ok(match self {
            Self::Unbounded => SpendLimit::Unbounded,
            Self::PerTransfer { rows, identity } => SpendLimit::PerTransfer { rows, identity },
            Self::PerWindow(window) => SpendLimit::PerWindow(Box::new(read(*window)?)),
        })
    }

    async fn map_window_async<V, E, F>(self, read: impl FnOnce(W) -> F) -> Result<SpendLimit<V>, E>
    where
        F: Future<Output = Result<V, E>>,
    {
        Ok(match self {
            Self::Unbounded => SpendLimit::Unbounded,
            Self::PerTransfer { rows, identity } => SpendLimit::PerTransfer { rows, identity },
            Self::PerWindow(window) => SpendLimit::PerWindow(Box::new(read(*window).await?)),
        })
    }
}

impl SpendLimitLookup<'_> {
    fn read<I: Rpc, R: Rpc>(
        self,
        env: ReadEnvironment<'_, I, R>,
    ) -> Result<SpendLimit<VelocityFacts>, TransferError> {
        self.map_window(|lookup| lookup.read(env))
    }

    async fn read_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        env: ReadEnvironment<'_, I, R>,
    ) -> Result<SpendLimit<VelocityFacts>, TransferError> {
        self.map_window_async(|lookup| lookup.read_async(env)).await
    }
}

struct VelocityLookup<'a> {
    read: ReadSpendRecord,
    context: VelocityContext<'a>,
}

impl VelocityLookup<'_> {
    fn read<I: Rpc, R: Rpc>(
        self,
        env: ReadEnvironment<'_, I, R>,
    ) -> Result<VelocityFacts, TransferError> {
        let head = self.read.current(env).map_err(list_entry)?;
        self.context.facts(head, env.rpc.get_slot()?)
    }

    async fn read_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        env: ReadEnvironment<'_, I, R>,
    ) -> Result<VelocityFacts, TransferError> {
        let head = self.read.current_async(env).await.map_err(list_entry)?;
        self.context.facts(head, env.rpc.get_slot().await?)
    }
}

/// The successor's blinding derives from the last output slot index.
struct RecordSlots<'a> {
    plan: &'a VelocityPlan,
    tx_viewing_key: &'a ViewingKey,
    sender_tag: ResolvedOwnerTag,
}

impl RecordSlots<'_> {
    fn append(self, proof_inputs: &mut SppProofInputs) -> Result<(), TransferError> {
        let Self {
            plan,
            tx_viewing_key,
            sender_tag,
        } = self;
        if proof_inputs.input_utxos.len() + 1 > plan.shape.n_inputs()
            || proof_inputs.output_utxos.len() + 1 > plan.shape.n_outputs()
        {
            return Err(TransferError::PolicyShapeUnsupported);
        }
        while proof_inputs.input_utxos.len() + 1 < plan.shape.n_inputs() {
            proof_inputs
                .input_utxos
                .push(SppProofInputUtxo::dummy(plan.input.tree_id)?);
        }

        let blindings = OutputBlindings::of(proof_inputs)?;
        RecordPadding {
            slots: plan.shape.n_outputs() - 1,
            sender_tag,
            blindings: &blindings,
        }
        .apply(proof_inputs)?;

        proof_inputs.input_utxos.push(plan.input.clone());
        let output = plan.output.clone();
        let slot_index = u32::try_from(proof_inputs.output_utxos.len())
            .map_err(|_| TransferError::PolicyShapeUnsupported)?;
        if output.blinding != blindings.at(slot_index)? {
            return Err(ClientError::OutputBlindingMismatch {
                index: slot_index as usize,
            }
            .into());
        }
        let address = output
            .owner_address
            .ok_or(TransactionError::OutputWithoutOwner {
                slot_index: slot_index as usize,
            })?;
        let resolved_owner_tag = address.signing_pubkey.confidential_view_tag()?;
        let encoded = Confidential::encode_plaintext(
            &ConfidentialOutputPlaintext {
                asset_id: output.asset.asset_id,
                amount: output.amount,
                blinding: output.blinding,
                ring_program_id: output.ring_program_id,
                data: output.data.clone(),
            },
            resolved_owner_tag,
            &ConfidentialEncode {
                tx: tx_viewing_key.clone(),
                recipient_pubkey: address.viewing_pubkey,
                salt: proof_inputs.external_data.salt,
                slot_index,
            },
        )?;
        proof_inputs.external_data.outputs.push(TransactOutput {
            utxo_hash: output.hash(proof_inputs.output_tree_id)?,
            owner_tag: OwnerTag::Inline(resolved_owner_tag),
            data: Some(encoded.data),
        });
        proof_inputs
            .external_data
            .resolved_owner_tags
            .push(resolved_owner_tag);
        proof_inputs.output_utxos.push(output);
        Ok(())
    }
}

struct OutputBlindings {
    first_nullifier: [u8; 32],
    seed: [u8; 32],
}

impl OutputBlindings {
    fn of(proof_inputs: &SppProofInputs) -> Result<Self, TransferError> {
        let first_nullifier = proof_inputs.first_nullifier()?;
        let seed = derive_output_blinding_seed(&first_nullifier, &proof_inputs.blinding_seed)?;
        Ok(Self {
            first_nullifier,
            seed,
        })
    }

    fn at(&self, slot_index: u32) -> Result<[u8; 32], TransferError> {
        Ok(derive_transact_output_blinding(
            &self.first_nullifier,
            &self.seed,
            slot_index,
        )?)
    }
}

struct RecordPadding<'a> {
    slots: usize,
    sender_tag: ResolvedOwnerTag,
    blindings: &'a OutputBlindings,
}

impl RecordPadding<'_> {
    fn apply(self, proof_inputs: &mut SppProofInputs) -> Result<(), TransferError> {
        while proof_inputs.output_utxos.len() < self.slots {
            let index = u32::try_from(proof_inputs.output_utxos.len())
                .map_err(|_| TransferError::PolicyShapeUnsupported)?;
            let output = SppProofOutputUtxo {
                blinding: self.blindings.at(index)?,
                ..Default::default()
            };
            proof_inputs.external_data.outputs.push(TransactOutput {
                utxo_hash: output.hash(proof_inputs.output_tree_id)?,
                // A tag unlike the sender's would reveal the real output count.
                owner_tag: self.sender_tag.tag,
                data: None,
            });
            proof_inputs
                .external_data
                .resolved_owner_tags
                .push(self.sender_tag.resolved);
            proof_inputs.output_utxos.push(output);
        }
        Ok(())
    }
}

pub(crate) struct PolicyTierInput<'a> {
    pub ring: CustomRing,
    pub inputs: &'a [SppProofInputUtxo],
    pub outputs: &'a [SppProofOutputUtxo],
    pub output_tree_id: u16,
    pub velocity: Option<VelocityProofInput>,
}

impl PolicyTierInput<'_> {
    pub fn read<I: Rpc, R: Rpc>(
        self,
        env: ReadEnvironment<'_, I, R>,
    ) -> Result<Tier, TransferError> {
        let pinned = self
            .ring
            .read_pinned_policy(env.rpc)?
            .ok_or(TransferError::MissingPolicyConfig)?;
        self.with_config(&pinned)?.build(env.indexer, env.rpc)
    }

    pub async fn read_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        env: ReadEnvironment<'_, I, R>,
    ) -> Result<Tier, TransferError> {
        let pinned = self
            .ring
            .read_pinned_policy_async(env.rpc)
            .await?
            .ok_or(TransferError::MissingPolicyConfig)?;
        self.with_config(&pinned)?
            .build_async(env.indexer, env.rpc)
            .await
    }

    pub fn with_config<'s>(self, pinned: &'s PinnedPolicy) -> Result<PolicyTier<'s>, TransferError>
    where
        Self: 's,
    {
        let (velocity, committed_velocity) = match self.velocity {
            Some(velocity) => (velocity, None),
            None => {
                if pinned.table.window_slots() != 0
                    && self.output_tree_id != pinned.config.address_tree_id()
                {
                    return Err(TransferError::TreeIdMismatch {
                        tree: pinned.config.address_tree,
                        expected: pinned.config.address_tree_id(),
                        found: self.output_tree_id,
                    });
                }
                // Record-free rails evaluate every money slot while still committing configured limits.
                let off = VelocityProofInput::off(RingIdentity::new(
                    self.ring,
                    pinned.config.namespace_owner_hash,
                )?);
                let mut committed = off;
                let rows = pinned.table.velocity();
                committed.window_slots = pinned.table.window_slots();
                committed.row_count = rows.len() as u8;
                committed.rows[..rows.len()].copy_from_slice(rows);
                (off, Some(committed))
            }
        };
        Ok(PolicyTier {
            committed_velocity,
            policy_config: &pinned.config,
            witness: CustomRingWitnessInput {
                policy: &pinned.table,
                policy_config: &pinned.config,
                inputs: self.inputs,
                outputs: self.outputs,
                output_tree_id: self.output_tree_id,
                velocity,
            },
        })
    }
}

pub(crate) struct PolicyTier<'a> {
    committed_velocity: Option<VelocityProofInput>,
    policy_config: &'a PolicyConfig,
    witness: CustomRingWitnessInput<'a>,
}

impl PolicyTier<'_> {
    pub fn build<I: Rpc, R: Rpc>(self, indexer: &I, rpc: &R) -> Result<Tier, TransferError> {
        let mut witness = self.witness.build(indexer, rpc)?;
        if let Some(velocity) = self.committed_velocity {
            witness.velocity = velocity;
        }
        Ok(Tier::policy(self.policy_config, witness))
    }

    pub async fn build_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        indexer: &I,
        rpc: &R,
    ) -> Result<Tier, TransferError> {
        let mut witness = self.witness.build_async(indexer, rpc).await?;
        if let Some(velocity) = self.committed_velocity {
            witness.velocity = velocity;
        }
        Ok(Tier::policy(self.policy_config, witness))
    }
}

/// A policy ring proves the folded statement over its entries-tree roots, an
/// audit-only ring proves the audit statement alone.
pub(crate) enum Tier {
    Base,
    Policy {
        policy_hash: [u8; 32],
        entries_tree: Address,
        witness: Box<CustomRingWitness>,
    },
}

impl Tier {
    fn policy(config: &PolicyConfig, witness: CustomRingWitness) -> Self {
        Self::Policy {
            policy_hash: config.policy_hash,
            entries_tree: config.address_tree,
            witness: Box::new(witness),
        }
    }
}

/// A transfer past validation and auditor encryption, waiting on the reads.
///
/// The stages are types, not flags: [`Self::witness`] consumes this one and is
/// the only way to reach [`WitnessedTransfer`], which is the only type
/// [`WitnessedTransfer::finish`] is defined on. Skipping a step, or repeating
/// one, does not compile, so no state has to be checked at run time and no
/// error variant has to stand in for "called out of order".
struct StagedTransfer {
    head_witness: Option<CompressedHead>,
    tx_viewing_key: ViewingKey,
    /// The sender's proof authority, which completes the built witness. Owned
    /// rather than borrowed: `stage` consumes the transfer, so the caller's
    /// reference does not outlive it.
    nullifier_key: Option<NullifierKey>,
    pending_proof: PendingCustomRingProof,
    proof_inputs: SppProofInputs,
    payer: Address,
    input_tree: Address,
    output_tree: Address,
    program_id: Address,
    interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    ring: CustomRing,
    cosigner: Option<Address>,
    velocity: Option<VelocityProofInput>,
    head_map_root: Option<Address>,
}

impl StagedTransfer {
    /// Every UTXO hash commits to its tree id, a prepared transfer under another id proves nothing.
    fn check_tree_ids(&self, input_tree_id: u16, output_tree_id: u16) -> Result<(), TransferError> {
        if let Some(input) = self
            .proof_inputs
            .input_utxos
            .iter()
            .find(|input| input.tree_id != input_tree_id)
        {
            return Err(TransferError::TreeIdMismatch {
                tree: self.input_tree,
                expected: input_tree_id,
                found: input.tree_id,
            });
        }
        if self.proof_inputs.output_tree_id != output_tree_id {
            return Err(TransferError::TreeIdMismatch {
                tree: self.output_tree,
                expected: output_tree_id,
                found: self.proof_inputs.output_tree_id,
            });
        }
        Ok(())
    }

    fn policy_tier<'s>(
        &'s self,
        pinned: &'s PinnedPolicy,
    ) -> Result<PolicyTier<'s>, TransferError> {
        PolicyTierInput {
            ring: self.ring,
            inputs: &self.proof_inputs.input_utxos,
            outputs: &self.proof_inputs.output_utxos,
            output_tree_id: self.proof_inputs.output_tree_id,
            velocity: self.velocity,
        }
        .with_config(pinned)
    }

    /// Builds the SPP ring witness over the message-bearing external data, then
    /// finishes the pending auditor encryption over the `private_tx_hash` that
    /// witness fixes, into the tier's proof request over the unchanged
    /// ciphertext. The program recomputes that same public-input chain from the
    /// payload and the config account.
    ///
    /// Both witnesses leave together because the second only ever needed the
    /// first's `private_tx_hash`, not its proof: a caller can then ask for both
    /// proofs at once.
    fn witness(self, spends: SpendSet, tier: Tier) -> Result<WitnessedTransfer, TransferError> {
        let tx_shape = self.proof_inputs.check_shape()?;
        let mut ring_result = RingTransferProver {
            inputs: spends.inputs,
            outputs: self.proof_inputs.output_utxos.clone(),
            blinding_seed: self.proof_inputs.blinding_seed,
            output_tree_id: self.proof_inputs.output_tree_id,
            external_data: self.proof_inputs.external_data.clone(),
            public_transfers: self.proof_inputs.public_transfers()?,
            signer_pk_hashes: self
                .proof_inputs
                .signer_pk_hashes(tx_shape.signer_width())?,
            allow_dummy_inputs: spends.allow_dummy_inputs,
            ring_program_id: Some(self.program_id),
            shape: tx_shape,
        }
        .build()?;
        // A windowed velocity transfer appends the namespace-owned spend
        // record as its final input. Its fixed zero authority is distinct from
        // the sender, so complete it first and let the sender authority skip
        // the now-complete slot.
        if self.head_witness.is_some() {
            let record = ring_result
                .inputs
                .inputs
                .last_mut()
                .ok_or(TransactionError::NoInputs)?;
            zero_nullifier_key().complete_inputs(std::slice::from_mut(record))?;
        }
        // Proof assembly deliberately leaves every real input's nullifier secret
        // absent. The caller's authority completes the inputs it owns and the
        // prover request rejects anything still incomplete.
        if let Some(authority) = self.nullifier_key.as_ref() {
            authority.complete_inputs(&mut ring_result.inputs.inputs)?;
        }
        let mut request = TierRequestInput {
            tier,
            pending: self.pending_proof,
            private_tx_hash: ring_result.private_tx_hash.try_into()?,
            external_data: &self.proof_inputs.external_data,
            private_tx_blinding: self.proof_inputs.private_tx_blinding()?,
        }
        .build()?;
        if let Some(head) = self.head_witness {
            request = request.with_head(head)?;
        }
        Ok(WitnessedTransfer {
            request,
            #[cfg(feature = "solana-rpc")]
            window: self.velocity.and_then(|velocity| velocity.window()),
            tx_viewing_key: self.tx_viewing_key,
            proof_inputs: self.proof_inputs,
            ring_result,
            payer: self.payer,
            input_tree: self.input_tree,
            output_tree: self.output_tree,
            interface_transfer_accounts: self.interface_transfer_accounts,
            ring: self.ring,
            cosigner: self.cosigner,
            head_map_root: self.head_map_root,
        })
    }
}

/// The tier's prover request, with the accounts and roots the instruction binds
/// for it.
pub(crate) enum TierRequest {
    Base(CustomRingBaseProofRequest),
    Policy {
        request: Box<CustomRingPolicyProofRequest>,
        entries_tree: Address,
        roots: TransactRoots,
        approval_required: bool,
        revocation_targets: [[u8; 32]; zolana_ring_policy::ANSWER_SLOTS],
        kind: PolicyProofKind,
    },
}

pub(crate) struct CompressedHead {
    pub transaction_salt: [u8; 16],
    pub counters_disclosure_hash: [u8; 32],
    pub witness: HeadWitness,
    pub transition: custom_ring_interface::HeadMapTransition,
}

pub(crate) enum PolicyProofKind {
    Ordinary,
    Compressed(Box<CompressedHead>),
    Delegate,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WrappedPolicyJson {
    circuit_type: &'static str,
    policy: CustomRingPolicyProofRequestJson,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CompressedPolicyJson {
    transaction_salt: String,
    #[serde(flatten)]
    wrapped: WrappedPolicyJson,
    #[serde(flatten)]
    head: HeadTransitionJson,
}

impl ProveRequest for TierRequest {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        match self {
            Self::Base(request) => request.body(),
            Self::Policy { request, kind, .. } => match kind {
                PolicyProofKind::Ordinary => request.body(),
                PolicyProofKind::Delegate => json_body(&WrappedPolicyJson {
                    circuit_type: "custom-ring-delegate-policy",
                    policy: request.json()?,
                }),
                PolicyProofKind::Compressed(head) => json_body(&CompressedPolicyJson {
                    transaction_salt: crate::instructions::transact::request::bytes_to_hex(
                        &head.transaction_salt,
                    ),
                    wrapped: WrappedPolicyJson {
                        circuit_type: "custom-ring-compressed-policy",
                        policy: request.json()?,
                    },
                    head: HeadTransitionJson::new(&head.witness, &head.transition),
                }),
            },
        }
    }

    fn delivery(&self) -> Delivery {
        match self {
            Self::Base(request) => request.delivery(),
            Self::Policy { request, .. } => request.delivery(),
        }
    }
}

pub(crate) struct TierRequestInput<'a> {
    pub tier: Tier,
    pub pending: PendingCustomRingProof,
    pub private_tx_hash: crate::CustomRingPrivateTxHash,
    pub external_data: &'a ExternalData,
    pub private_tx_blinding: [u8; 32],
}

impl TierRequestInput<'_> {
    /// Closes the auditor encryption over the `private_tx_hash` the SPP witness fixed.
    pub(crate) fn build(self) -> Result<TierRequest, TransferError> {
        Ok(match self.tier {
            Tier::Base => TierRequest::Base(self.pending.finish_base(self.private_tx_hash)?),
            Tier::Policy {
                policy_hash,
                entries_tree,
                witness,
            } => {
                let external_data_hash = self
                    .external_data
                    .hash()
                    .map_err(|_| TransferError::PolicyHashing)?;
                let roots = witness.roots;
                let approval_required = witness.velocity.approval_required;
                let revocation_targets = witness.revocation_targets;
                let request = self.pending.finish(
                    self.private_tx_hash,
                    &external_data_hash,
                    &self.private_tx_blinding,
                    *witness,
                    &policy_hash,
                )?;
                TierRequest::Policy {
                    request: Box::new(request),
                    entries_tree,
                    roots,
                    approval_required,
                    revocation_targets,
                    kind: PolicyProofKind::Ordinary,
                }
            }
        })
    }
}

impl TierRequest {
    /// The compressed circuit folds both roots after the policy chain.
    fn with_head(mut self, head: CompressedHead) -> Result<Self, TransferError> {
        let Self::Policy { request, kind, .. } = &mut self else {
            return Err(TransferError::HeadWithoutWindow);
        };
        if request.velocity.window_slots == 0 {
            return Err(TransferError::HeadWithoutWindow);
        }
        use zolana_hasher::{Hasher, Poseidon};
        let old = Poseidon::hashv(&[&request.public_input_hash, &head.transition.old_root])
            .map_err(|_| TransferError::PolicyHashing)?;
        request.public_input_hash = Poseidon::hashv(&[&old, &head.transition.new_root])
            .map_err(|_| TransferError::PolicyHashing)?;
        request.public_input_hash =
            Poseidon::hashv(&[&request.public_input_hash, &head.counters_disclosure_hash])
                .map_err(|_| TransferError::PolicyHashing)?;
        *kind = PolicyProofKind::Compressed(Box::new(head));
        Ok(self)
    }

    pub(crate) fn for_delegate(mut self) -> Self {
        if let Self::Policy { kind, .. } = &mut self {
            *kind = PolicyProofKind::Delegate;
        }
        self
    }

    pub fn proven(self, proof: Proof) -> Result<TierBinding, TransferError> {
        let proof = to_instruction_proof(proof)?;
        Ok(match self {
            Self::Base(_) => TierBinding {
                proof,
                entries_tree: None,
                state_root_index: 0,
                nullifier_root_index: 0,
                approval_required: false,
                revocation_targets: [[0u8; 32]; zolana_ring_policy::ANSWER_SLOTS],
                head_transition: None,
            },
            Self::Policy {
                entries_tree,
                roots,
                approval_required,
                revocation_targets,
                kind,
                ..
            } => TierBinding {
                proof,
                entries_tree: Some(entries_tree),
                state_root_index: roots.state_index,
                nullifier_root_index: roots.nullifier_index,
                approval_required,
                revocation_targets,
                head_transition: match kind {
                    PolicyProofKind::Compressed(head) => Some(head.transition),
                    _ => None,
                },
            },
        })
    }
}

pub(crate) struct TierBinding {
    pub proof: CustomRingProof,
    pub entries_tree: Option<Address>,
    pub state_root_index: u16,
    pub nullifier_root_index: u16,
    pub approval_required: bool,
    pub revocation_targets: [[u8; 32]; zolana_ring_policy::ANSWER_SLOTS],
    pub head_transition: Option<custom_ring_interface::HeadMapTransition>,
}

/// Both witnesses built and the auditor encryption closed over the transfer's
/// `private_tx_hash`. Only the two proofs are outstanding.
struct WitnessedTransfer {
    request: TierRequest,
    #[cfg(feature = "solana-rpc")]
    window: Option<ProvedWindow>,
    tx_viewing_key: ViewingKey,
    proof_inputs: SppProofInputs,
    ring_result: RingTransferProofResult,
    payer: Address,
    input_tree: Address,
    output_tree: Address,
    interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    ring: CustomRing,
    cosigner: Option<Address>,
    head_map_root: Option<Address>,
}

impl WitnessedTransfer {
    /// The SPP transfer witness to prove.
    fn spp(&self) -> &TransferInputs {
        &self.ring_result.inputs
    }

    fn finish(
        self,
        spp_proof: TransactProof,
        ring_proof: Proof,
    ) -> Result<ProvenTransfer, TransferError> {
        let TierBinding {
            proof,
            entries_tree,
            state_root_index,
            nullifier_root_index,
            approval_required,
            revocation_targets,
            head_transition,
        } = self.request.proven(ring_proof)?;
        let n_inputs = self.proof_inputs.check_shape()?.n_inputs();
        Ok(ProvenTransfer {
            #[cfg(feature = "solana-rpc")]
            window: self.window,
            tx_viewing_key: self.tx_viewing_key,
            data: RingInstructionData {
                external_data: &self.proof_inputs.external_data,
                nullifiers: &self.ring_result.nullifiers,
                input_tree_indexes: &self.ring_result.input_tree_indexes,
                tree_contexts: &self.ring_result.tree_contexts,
                private_tx_hash: self.ring_result.private_tx_hash,
                proof: spp_proof,
                circuit: CircuitId::RingEddsa(
                    n_inputs as u8,
                    self.proof_inputs.external_data.outputs.len() as u8,
                    N_PUBLIC_SLOTS as u8,
                ),
            }
            .assemble()?,
            proof,
            owner_signers: self.proof_inputs.owner_signer_pubkeys()?,
            interface_transfer_accounts: self.interface_transfer_accounts,
            state_root_index,
            nullifier_root_index,
            cosigner: self.cosigner,
            approval_required,
            revocation_targets,
            head_transition,
            payer: self.payer,
            input_tree: self.input_tree,
            output_tree: self.output_tree,
            entries_tree,
            head_map_root: self.head_map_root,
            ring: self.ring,
        })
    }
}

impl ProvenTransfer {
    pub fn instruction(&self) -> Result<Instruction, TransferError> {
        CustomRingTransact {
            ring: self.ring,
            payer: self.payer,
            input_tree: self.input_tree,
            output_tree: self.output_tree,
            entries_tree: self.entries_tree,
            head_map_root: self.head_map_root,
            cosigner: self.cosigner,
            owner_signers: self.owner_signers.clone(),
            interface_transfer_accounts: self.interface_transfer_accounts.clone(),
            proof: self.proof,
            transact: self.data.clone(),
            state_root_index: self.state_root_index,
            nullifier_root_index: self.nullifier_root_index,
            approval_required: self.approval_required,
            revocation_targets: self.revocation_targets,
            head_transition: self.head_transition,
        }
        .instruction()
        .map_err(Into::into)
    }
}

impl RingDeposit<'_> {
    pub fn send<R: Rpc>(
        self,
        env: DepositProofEnvironment<'_, R>,
    ) -> Result<RingDepositReceipt, DepositError> {
        let rpc = env.rpc;
        let address = self.asset.mint();
        let mint = if address == zolana_transaction::SOL_MINT {
            Mint::SOL
        } else {
            let registry = zolana_interface::pda::spl_asset_registry(&address);
            let account = rpc
                .get_account(registry)?
                .ok_or(ClientError::AccountNotFound {
                    address: registry.to_bytes(),
                })?;
            let record =
                zolana_interface::state::SplAssetRegistry::from_account_bytes(&account.data)
                    .map_err(|error| {
                        ClientError::Rpc(format!("invalid asset registry: {error:?}"))
                    })?;
            if record.mint != address || account.owner.to_bytes() != SHIELDED_POOL_PROGRAM_ID {
                return Err(ClientError::Rpc("asset registry mismatch".into()).into());
            }
            Mint::new(address, record.asset_id)
        };
        let config = self
            .ring
            .read_config(rpc)?
            .ok_or(DepositError::MissingRingConfig)?;
        let blinding = random_blinding();
        let owner_hash = self.recipient.owner_hash()?;
        let mut deposit = RingAssetDeposit {
            asset: self.asset,
            view_tag: self.recipient.recipient_bootstrap_view_tag(),
            owner_utxo_hash: owner_utxo_hash(&owner_hash, &blinding)?,
            amount: self.amount,
            data_hash: None,
            ring_data_hash: NO_RING_DATA_HASH,
            encrypted: RingDepositPlaintext {
                blinding,
                utxo_data: None,
                memo: None,
                ring_data: Vec::new(),
            }
            .encrypt(&self.recipient.viewing_pubkey())?,
        };
        // 1. The on-chain setting selects disclosure proving before any deposit
        // is sent.
        let proof = if self.ring.read_deposit_audit(rpc)? {
            let encryption = DepositSeal {
                openings: &[DepositOpening {
                    owner_hash,
                    blinding: Zeroizing::new(blinding),
                }],
                auditor_pk: &config.auditor_pubkey,
            }
            .seal()?;
            deposit.encrypted.ciphertext = RingDepositAuditCapsule {
                slot_index: 0,
                eph_pk: encryption.ephemeral_pk.as_bytes(),
                ciphertext: &encryption.ciphertexts[0],
                recipient_ciphertext: &deposit.encrypted.ciphertext,
            }
            .encode();
            let spp_instruction = zolana_interface::instruction::RingDeposit {
                tree: self.tree,
                depositor: self.payer.pubkey(),
                ring_program_id: self.ring.program_id(),
                deposits: vec![deposit.clone()],
            }
            .instruction()?;
            // 2. The proof binds the ring, destination tree and exact forwarded
            // SPP bytes.
            let context_hash = custom_ring_interface::DepositContext {
                program_id: self.ring.program_id().as_array(),
                tree: self.tree.as_array(),
                spp_data: &spp_instruction.data,
            }
            .hash()
            .map_err(|_| DepositError::Hashing)?;
            let public_input_hash = custom_ring_interface::DepositPublicInput {
                context_hash: &context_hash,
                owner_utxo_hashes: &[deposit.owner_utxo_hash],
                ciphertexts: &encryption.ciphertexts,
                auditor_pk: config.auditor_pubkey.as_bytes(),
                eph_pk: encryption.ephemeral_pk.as_bytes(),
                key_registry_root: None,
            }
            .hash()
            .map_err(|_| DepositError::Hashing)?;
            let mut owner_hashes = [[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
            owner_hashes[0] = owner_hash;
            let mut blindings = Zeroizing::new([[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS]);
            blindings[0] = blinding;
            let uncompressed = config.auditor_pubkey.to_p256()?.to_encoded_point(false);
            let mut auditor_pk = [0; 65];
            auditor_pk.copy_from_slice(uncompressed.as_bytes());
            Some(to_instruction_proof(env.prover.prove(
                &crate::instructions::deposit_request::RingDepositProofRequest {
                    public_input_hash: &public_input_hash,
                    context_hash: &context_hash,
                    count: 1,
                    owner_hashes: &owner_hashes,
                    blindings: &blindings,
                    ephemeral_sk: &encryption.ephemeral_sk,
                    auditor_pk: &auditor_pk,
                },
            )?)?)
        } else {
            None
        };
        let ix = Deposit {
            ring: self.ring,
            tree: self.tree,
            depositor: self.payer.pubkey(),
            deposits: vec![deposit],
            proof,
            cosigner: self.cosigner.map(Signer::pubkey),
            has_policy: config.has_policy,
        }
        .instruction()?;
        let mut signers = vec![self.payer];
        signers.extend(self.cosigner);
        let signature = rpc.create_and_send_transaction(
            core::slice::from_ref(&ix),
            self.payer.pubkey(),
            &signers,
            if proof.is_some() {
                ComputeBudgetConfig::new(crate::AUDITED_DEPOSIT_COMPUTE_UNIT_LIMIT)
            } else {
                ComputeBudgetConfig::for_instruction_count(1)
            },
        )?;
        Ok(RingDepositReceipt {
            signature,
            utxo: Utxo {
                owner: self.recipient.signing_pubkey(),
                asset: mint,
                amount: self.amount,
                blinding,
                ring_program_id: Some(self.ring.program_id()),
                data: Data::default(),
            },
        })
    }
}

/// The raw id of a pool tree, every UTXO in it hashes under this id.
pub fn tree_id<R: Rpc>(rpc: &R, tree: Address) -> Result<u16, TransferError> {
    Ok(read_tree_state(rpc, tree)?.tree.id)
}

pub async fn tree_id_async<R: AsyncRpc>(rpc: &R, tree: Address) -> Result<u16, TransferError> {
    Ok(read_tree_state_async(rpc, tree).await?.tree.id)
}

#[derive(Clone, Copy)]
pub(crate) struct BoundTree {
    pub address: Address,
    pub id: u16,
}

pub(crate) struct TreeState {
    /// Nullifier slots left above the state tree's full capacity, queued ones counted.
    pub dummy_input_headroom: u64,
    pub tree: BoundTree,
}

impl TreeState {
    /// SPP derives the same flag from this tree and the transaction's input count.
    pub fn allows_dummy_inputs(&self, inputs: &[SppProofInputUtxo]) -> bool {
        self.dummy_input_headroom >= inputs.len() as u64
    }
}

pub(crate) fn read_tree_state<R: Rpc>(rpc: &R, tree: Address) -> Result<TreeState, TransferError> {
    tree_state(rpc.get_account(tree)?, tree)
}

pub(crate) async fn read_tree_state_async<R: AsyncRpc>(
    rpc: &R,
    tree: Address,
) -> Result<TreeState, TransferError> {
    tree_state(rpc.get_account(tree).await?, tree)
}

/// Reading the state out of a fetched tree account is transport-independent.
fn tree_state(account: Option<Account>, tree: Address) -> Result<TreeState, TransferError> {
    let mut account = account.ok_or(TransferError::MissingTree)?;
    if account.owner.to_bytes() != SHIELDED_POOL_PROGRAM_ID {
        return Err(TransferError::InvalidTreeOwner);
    }
    if account.data.first() != Some(&TREE_ACCOUNT_DISCRIMINATOR) {
        return Err(TransferError::InvalidTreeDiscriminator);
    }
    let tree_account = TreeAccount::from_bytes(&mut account.data, tree.to_bytes())?;
    Ok(TreeState {
        dummy_input_headroom: tree_account.dummy_input_headroom()?,
        tree: BoundTree {
            address: tree,
            id: tree_account.tree_id(),
        },
    })
}

pub(crate) struct RingMembership<'a> {
    pub program_id: Address,
    pub inputs: &'a [SppProofInputUtxo],
    pub outputs: &'a [SppProofOutputUtxo],
}

impl RingMembership<'_> {
    pub fn validate(self) -> Result<(), TransferError> {
        let foreign = self
            .inputs
            .iter()
            .map(|input| input.utxo.ring_program_id)
            .chain(self.outputs.iter().map(|output| output.ring_program_id))
            .flatten()
            .find(|program_id| *program_id != self.program_id);
        if let Some(program_id) = foreign {
            return Err(TransferError::ForeignRing(program_id));
        }
        let data_outside = self
            .inputs
            .iter()
            .map(|input| (input.utxo.ring_program_id, input.ring_data_hash))
            .chain(
                self.outputs
                    .iter()
                    .map(|output| (output.ring_program_id, output.ring_data_hash)),
            )
            .any(|(ring, data)| ring.is_none() && data.is_some());
        if data_outside {
            return Err(TransferError::RingDataOutsideRing);
        }
        Ok(())
    }
}

fn validate_transfer_accounts(
    transaction: &ConfidentialTransaction,
    accounts: &[TransactInterfaceTransferAccounts],
) -> Result<(), TransferError> {
    let transfers = transaction
        .interface_transfers()?
        .into_iter()
        .map(|transfer| transfer.interface_transfer())
        .collect::<Vec<_>>();
    SettlementAccountValidation {
        transfers: &transfers,
        accounts,
    }
    .validate()?;
    Ok(())
}

/// A dummy copies the length of a real slot with its ring binding, else of the first real slot.
pub(crate) fn frame_dummy_outputs(
    outputs: &[SppProofOutputUtxo],
    encoded: &mut [TransactOutput],
) -> Result<(), TransferError> {
    let templates: Vec<(bool, usize)> = outputs
        .iter()
        .zip(encoded.iter())
        .filter(|(output, _)| !output.is_dummy())
        .map(|(output, encoded)| {
            encoded
                .data
                .as_ref()
                .map(|data| (output.ring_program_id.is_some(), data.len()))
                .ok_or(TransferError::InvalidDummyOutput)
        })
        .collect::<Result<_, _>>()?;
    for (output, encoded) in outputs.iter().zip(encoded.iter_mut()) {
        if !output.is_dummy() {
            continue;
        }
        let in_ring = output.ring_program_id.is_some();
        let template = templates
            .iter()
            .find(|(ring, _)| *ring == in_ring)
            .or_else(|| templates.first())
            .copied();
        let key = ViewingKey::new().pubkey();
        let ciphertext_len = match template {
            Some((_, encoded_len)) => encoded_len
                .checked_sub(1 + 4 + 1 + key.as_bytes().len())
                .filter(|len| *len > 0)
                .ok_or(TransferError::InvalidDummyOutput)?,
            None => ConfidentialOutputPlaintext {
                asset_id: zolana_transaction::SOL_ASSET_ID,
                amount: 0,
                blinding: [0; 32],
                ring_program_id: output.ring_program_id,
                data: Data::default(),
            }
            .serialize()?
            .len(),
        };
        let mut ciphertext = vec![0u8; ciphertext_len];
        OsRng.fill_bytes(&mut ciphertext);
        let mut body = Vec::with_capacity(1 + key.as_bytes().len() + ciphertext_len);
        body.push(if in_ring {
            EncryptedScheme::RingConfidential.as_byte()
        } else {
            EncryptedScheme::Confidential.as_byte()
        });
        body.extend_from_slice(key.as_bytes());
        body.extend_from_slice(&ciphertext);
        encoded.data = Some(borsh::to_vec(&OutputDataEncoding::Encrypted(body))?);
    }
    Ok(())
}

pub(crate) struct SpendSet {
    pub inputs: Vec<TransferInputUtxo>,
    pub allow_dummy_inputs: bool,
}

/// The two indexer queries one spend set needs.
///
/// Named fields rather than a pair of `Vec<[u8; 32]>`: the two have the same
/// type, so a tuple lets a caller hand the nullifiers to the inclusion query and
/// the hashes to the non-inclusion one without the compiler noticing.
struct SpendQueries {
    /// Hashes of the real spends, whose inclusion in the tree is proved.
    utxo_hashes: Vec<[u8; 32]>,
    /// Nullifiers of every spend, real and dummy, whose absence is proved.
    nullifiers: Vec<[u8; 32]>,
}

#[must_use = "use the updated transfer"]
pub(crate) struct RingSpendInputs<'a, I> {
    pub indexer: &'a I,
    pub tree: Address,
    pub input_utxos: &'a [SppProofInputUtxo],
}

impl<'a, I> RingSpendInputs<'a, I> {
    /// The hashes to prove inclusion for, and the nullifiers to prove absence
    /// of. Independent of transport.
    fn queries(&self) -> SpendQueries {
        let utxo_hashes = self
            .input_utxos
            .iter()
            .filter(|input_utxo| !input_utxo.is_dummy())
            .map(SppProofInputUtxo::hash)
            .collect::<Vec<_>>();
        let nullifiers = self
            .input_utxos
            .iter()
            .map(SppProofInputUtxo::nullifier)
            .collect::<Vec<_>>();
        SpendQueries {
            utxo_hashes,
            nullifiers,
        }
    }
}

impl<I: AsyncRpc> RingSpendInputs<'_, I> {
    pub async fn load_async(self) -> Result<Vec<TransferInputUtxo>, TransferError> {
        let SpendQueries {
            utxo_hashes,
            nullifiers,
        } = self.queries();
        let states = self
            .indexer
            .get_merkle_proofs(self.tree, utxo_hashes, None)
            .await?
            .proofs;
        let non_inclusions = self
            .indexer
            .get_non_inclusion_proofs(self.tree, nullifiers, None)
            .await?
            .proofs;
        self.assemble(states, non_inclusions)
    }
}

impl<I: Rpc> RingSpendInputs<'_, I> {
    pub fn load(self) -> Result<Vec<TransferInputUtxo>, TransferError> {
        let SpendQueries {
            utxo_hashes,
            nullifiers,
        } = self.queries();
        let states = self
            .indexer
            .get_merkle_proofs(self.tree, utxo_hashes, None)?
            .proofs;
        let non_inclusions = self
            .indexer
            .get_non_inclusion_proofs(self.tree, nullifiers, None)?
            .proofs;
        self.assemble(states, non_inclusions)
    }
}

impl<I> RingSpendInputs<'_, I> {
    /// Pairs each spend with its proofs. Both transports share this.
    fn assemble(
        self,
        states: Vec<MerkleProof>,
        non_inclusions: Vec<NonInclusionProof>,
    ) -> Result<Vec<TransferInputUtxo>, TransferError> {
        let real_count = self
            .input_utxos
            .iter()
            .filter(|input_utxo| !input_utxo.is_dummy())
            .count();
        if states.len() != real_count || non_inclusions.len() != self.input_utxos.len() {
            return Err(TransferError::IncompleteProofSet);
        }
        let mut states = states.into_iter();
        self.input_utxos
            .iter()
            .zip(non_inclusions)
            .map(|(input_utxo, nullifier)| {
                let (proof, nullifier_proof) = if input_utxo.is_dummy() {
                    (None, Some(nullifier))
                } else {
                    let state = states.next().ok_or(TransferError::IncompleteProofSet)?;
                    (Some(SpendProof { state, nullifier }), None)
                };
                Ok(TransferInputUtxo {
                    utxo: input_utxo.clone(),
                    proof,
                    nullifier_proof,
                })
            })
            .collect()
    }
}

#[must_use]
pub(crate) struct RingInstructionData<'a> {
    pub external_data: &'a ExternalData,
    pub nullifiers: &'a [[u8; 32]],
    pub input_tree_indexes: &'a [u8],
    pub tree_contexts: &'a [zolana_interface::instruction::TreeContext],
    pub private_tx_hash: [u8; 32],
    pub proof: TransactProof,
    pub circuit: CircuitId,
}

impl RingInstructionData<'_> {
    pub fn assemble(self) -> Result<TransactIxData, TransferError> {
        let inputs = input_utxos_from_nullifiers(self.nullifiers, self.input_tree_indexes)?;
        if inputs.len() != usize::from(self.circuit.num_inputs()) {
            return Err(TransferError::IncompleteInputSet);
        }

        let external = self.external_data;
        Ok(TransactIxData {
            proof: self.proof,
            expiry_unix_ts: external.expiry_unix_ts,
            private_tx_hash: self.private_tx_hash,
            circuit: self.circuit,
            inputs,
            tree_contexts: self.tree_contexts.to_vec(),
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
        })
    }
}

#[cfg(test)]
mod tests {
    use zolana_client::MerkleContext;
    use zolana_interface::instruction::{
        instruction_data::transact::{
            confidential_encrypted_output_body, ring_confidential_encrypted_output_body,
        },
        TransactSolTransferAccounts,
    };
    use zolana_transaction::keys::LocalShieldedKeys;
    use zolana_transaction::Mint;

    use super::*;

    fn ring() -> CustomRing {
        CustomRing::new(Address::new_from_array([42u8; 32]))
    }

    #[test]
    fn spend_proofs_carry_the_note_data_hashes() {
        let owner = ShieldedKeypair::new_ed25519().expect("owner");
        let input_utxos = [zolana_test_utils::utxo::wallet(
            Utxo {
                owner: owner.signing_pubkey(),
                asset: Mint::SOL,
                amount: 5,
                blinding: [1u8; 32],
                ring_program_id: None,
                data: Data::default(),
            },
            &owner.nullifier_key,
            0,
            0,
            Some([7; 32]),
            Some([8; 32]),
        )
        .expect("input")
        .into()];
        let merkle = MerkleProof {
            leaf: [2u8; 32],
            merkle_context: MerkleContext {
                tree_type: 0,
                tree: Address::default(),
            },
            path: vec![[0u8; 32]; 32],
            leaf_index: 0,
            root: [3u8; 32],
            root_seq: 1,
            root_index: 0,
        };
        let non_inclusion = NonInclusionProof {
            leaf: [4u8; 32],
            merkle_context: MerkleContext {
                tree_type: 1,
                tree: Address::default(),
            },
            path: vec![[0u8; 32]; 40],
            low_element: [5u8; 32],
            low_element_index: 0,
            high_element: [6u8; 32],
            high_element_index: 1,
            root: [9u8; 32],
            root_seq: 1,
            root_index: 0,
        };
        let inputs = RingSpendInputs {
            indexer: &(),
            tree: Address::default(),
            input_utxos: &input_utxos,
        }
        .assemble(vec![merkle], vec![non_inclusion])
        .expect("one real input_utxo pairs with its proofs");
        let input = inputs.first().expect("one assembled input_utxo");
        assert_eq!(input.utxo.data_hash, Some([7u8; 32]));
        assert_eq!(input.utxo.ring_data_hash, Some([8u8; 32]));
    }

    fn prepared_transfer(amount: u64) -> (ShieldedKeypair, ConfidentialTransaction) {
        let sender = ShieldedKeypair::new_ed25519().expect("sender");
        let recipient = ShieldedKeypair::new_ed25519().expect("recipient");
        let input = zolana_test_utils::utxo::wallet(
            Utxo {
                owner: sender.signing_pubkey(),
                asset: Mint::SOL,
                amount: 10,
                blinding: random_blinding(),
                ring_program_id: Some(ring().program_id()),
                data: Data::default(),
            },
            &sender.nullifier_key,
            0,
            0,
            None,
            None,
        )
        .expect("input");
        let mut transfer =
            ConfidentialTransaction::new(vec![input], solana_signer::Signer::pubkey(&sender))
                .expect("transaction");
        transfer
            .transfer_sol(&recipient.shielded_address().unwrap(), amount)
            .unwrap();
        transfer
            .pad_utxos(
                zolana_interface::shape::Shape::IN2_OUT3,
                &sender.shielded_address().unwrap(),
            )
            .unwrap();
        (sender, transfer)
    }

    #[test]
    fn membership_accepts_active_and_default_outputs() {
        let (_sender, prepared) = prepared_transfer(4);
        let inputs = prepared
            .inputs()
            .iter()
            .map(SppProofInputUtxo::from)
            .collect::<Vec<_>>();
        let mut outputs = prepared.outputs().to_vec();
        RingMembership {
            program_id: ring().program_id(),
            inputs: &inputs,
            outputs: &outputs,
        }
        .validate()
        .expect("default outputs");
        outputs[1].ring_program_id = Some(ring().program_id());
        RingMembership {
            program_id: ring().program_id(),
            inputs: &inputs,
            outputs: &outputs,
        }
        .validate()
        .expect("active ring output");
        outputs[1].ring_program_id = Some(Address::new_from_array([9u8; 32]));
        assert!(matches!(
            RingMembership {
                program_id: ring().program_id(),
                inputs: &inputs,
                outputs: &outputs,
            }
            .validate(),
            Err(TransferError::ForeignRing(_))
        ));
    }

    #[test]
    fn membership_refuses_ring_data_outside_a_ring() {
        let (_sender, prepared) = prepared_transfer(4);
        let inputs = prepared
            .inputs()
            .iter()
            .map(SppProofInputUtxo::from)
            .collect::<Vec<_>>();
        let mut outputs = prepared.outputs().to_vec();
        outputs[1].ring_data_hash = Some([3u8; 32]);
        assert!(matches!(
            RingMembership {
                program_id: ring().program_id(),
                inputs: &inputs,
                outputs: &outputs,
            }
            .validate(),
            Err(TransferError::RingDataOutsideRing)
        ));
        outputs[1].ring_program_id = Some(ring().program_id());
        RingMembership {
            program_id: ring().program_id(),
            inputs: &inputs,
            outputs: &outputs,
        }
        .validate()
        .expect("ring data inside the ring");
    }

    #[test]
    fn withdrawal_accounts_are_validated_before_proving() {
        let (sender, _) = prepared_transfer(4);
        let input = zolana_test_utils::utxo::wallet(
            Utxo {
                owner: sender.signing_pubkey(),
                asset: Mint::SOL,
                amount: 10,
                blinding: random_blinding(),
                ring_program_id: Some(ring().program_id()),
                data: Data::default(),
            },
            &sender.nullifier_key,
            0,
            0,
            None,
            None,
        )
        .unwrap();
        let recipient = Address::new_from_array([7; 32]);
        let mut prepared =
            ConfidentialTransaction::new(vec![input], solana_signer::Signer::pubkey(&sender))
                .unwrap();
        prepared.withdraw_sol(4, recipient).unwrap();
        assert!(matches!(
            validate_transfer_accounts(&prepared, &[]),
            Err(TransferError::Client(
                ClientError::SettlementTransferCountMismatch { .. }
            ))
        ));
        validate_transfer_accounts(
            &prepared,
            &[TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts { recipient },
            )],
        )
        .expect("withdrawal accounts");
    }

    /// Every `AsyncRpc` method has a default, so an empty type is a valid one.
    struct NoRpc;
    impl AsyncRpc for NoRpc {}

    #[test]
    fn the_async_prove_future_is_send() {
        // A host reaches for the async path because it runs on a multi-threaded
        // runtime; a future that cannot cross threads is no use to it. The
        // `Send + Sync` bound on `sender` is what makes this hold, and dropping
        // it fails here rather than in whatever server tries to await it.
        //
        // This only type-checks the future. Running one to completion against a
        // live chain, prover and indexer -- and comparing it against a blocking
        // proof of the same note -- is `auditor_sees_every_ring_transfer` in
        // custom-rings/test/tests/ring.rs.
        fn assert_send<F: Send>(_: F) {}

        let (keypair, prepared) = prepared_transfer(4);
        let prover = AsyncProverClient::new(String::new());
        let rpc = NoRpc;
        assert_send(
            CustomRingTransfer::new(CustomRingTransferInput {
                ring: ring(),
                sender: &keypair,
                nullifier_key: Some(&keypair.nullifier_key),
                transaction: prepared,
            })
            .prove_async(AsyncTransferProofEnvironment {
                indexer: &rpc,
                rpc: &rpc,
                prover: &prover,
            }),
        );
    }

    #[test]
    fn keys_without_a_signing_secret_can_build_a_transfer() {
        let (keypair, prepared) = prepared_transfer(4);
        let first_nullifier = *prepared.first_nullifier();
        let keys = LocalShieldedKeys::from_keypair(&keypair).unwrap();

        let transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring: ring(),
            sender: &keys,
            nullifier_key: Some(&keypair.nullifier_key),
            transaction: prepared,
        });

        let derived = transfer
            .sender
            .transaction_keys(&[TransactionKeyRequest {
                viewing_pubkey: keypair.viewing_pubkey(),
                first_nullifier,
            }])
            .unwrap();
        assert_eq!(
            derived[0].pubkey(),
            keypair
                .get_transaction_viewing_key(&first_nullifier)
                .unwrap()
                .pubkey()
        );
    }

    fn framed_fixture(rings: &[Option<Address>]) -> SppProofInputs {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        let input = zolana_test_utils::utxo::wallet(
            Utxo {
                owner: sender.signing_pubkey(),
                asset: Mint::SOL,
                amount: rings.len() as u64,
                blinding: random_blinding(),
                ring_program_id: None,
                data: Data::default(),
            },
            &sender.nullifier_key,
            0,
            0,
            None,
            None,
        )
        .unwrap();
        let mut tx =
            ConfidentialTransaction::new(vec![input], solana_signer::Signer::pubkey(&sender))
                .unwrap();
        for ring in rings {
            tx.transfer_with_ring(&sender.shielded_address().unwrap(), Mint::SOL, 1, *ring)
                .unwrap();
        }
        tx.encrypt(&sender).unwrap()
    }

    #[test]
    fn record_padding_is_tagged_like_the_sender_change() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        let input = zolana_test_utils::utxo::wallet(
            Utxo {
                owner: sender.signing_pubkey(),
                asset: Mint::SOL,
                amount: 1,
                blinding: random_blinding(),
                ring_program_id: None,
                data: Data::default(),
            },
            &sender.nullifier_key,
            0,
            0,
            None,
            None,
        )
        .unwrap();
        let mut tx =
            ConfidentialTransaction::new(vec![input], solana_signer::Signer::pubkey(&sender))
                .unwrap();
        tx.transfer_with_ring(&sender.shielded_address().unwrap(), Mint::SOL, 1, None)
            .unwrap();
        let sender_tag = tx.sender_owner_tag(&sender.signing_pubkey()).unwrap();
        let mut proof_inputs = tx.encrypt(&sender).unwrap();
        let real = proof_inputs.external_data.outputs.len();
        let blindings = OutputBlindings::of(&proof_inputs).unwrap();
        RecordPadding {
            slots: real + 2,
            sender_tag,
            blindings: &blindings,
        }
        .apply(&mut proof_inputs)
        .unwrap();
        let change = &proof_inputs.external_data.outputs[0];
        assert_ne!(sender_tag.resolved, [0; 32]);
        for slot in real..real + 2 {
            assert!(proof_inputs.output_utxos[slot].is_dummy());
            assert_eq!(
                proof_inputs.external_data.outputs[slot].owner_tag,
                change.owner_tag
            );
            assert_eq!(
                proof_inputs.external_data.resolved_owner_tags[slot],
                proof_inputs.external_data.resolved_owner_tags[0]
            );
        }
    }

    #[test]
    fn output_framing_selects_ring_membership() {
        for binding in [None, Some(ring().program_id())] {
            let tx = framed_fixture(&[binding, binding, binding]);
            for slot in &tx.external_data.outputs {
                let data = slot.data.as_deref().unwrap();
                assert_eq!(
                    ring_confidential_encrypted_output_body(data).is_some(),
                    binding.is_some()
                );
                assert_eq!(
                    confidential_encrypted_output_body(data).is_some(),
                    binding.is_none()
                );
            }
        }
    }

    #[test]
    fn a_dummy_takes_the_length_of_a_real_slot_with_its_own_binding() {
        let mut proof_inputs = framed_fixture(&[None, Some(ring().program_id()), None]);
        proof_inputs.output_utxos[2].owner_address = None;
        let real_len = |in_ring: bool| {
            proof_inputs
                .output_utxos
                .iter()
                .zip(&proof_inputs.external_data.outputs)
                .find(|(output, _)| {
                    !output.is_dummy() && output.ring_program_id.is_some() == in_ring
                })
                .and_then(|(_, output)| output.data.as_ref().map(Vec::len))
                .expect("real output data")
        };
        let (ring_len, default_len) = (real_len(true), real_len(false));
        assert_ne!(ring_len, default_len);
        frame_dummy_outputs(
            &proof_inputs.output_utxos,
            &mut proof_inputs.external_data.outputs,
        )
        .expect("mixed framing");
        assert!(proof_inputs
            .output_utxos
            .iter()
            .any(|output| output.is_dummy()));
        for (output, encoded) in proof_inputs
            .output_utxos
            .iter()
            .zip(&proof_inputs.external_data.outputs)
            .filter(|(output, _)| output.is_dummy())
        {
            let data = encoded.data.as_deref().expect("dummy output data");
            assert_eq!(data.len(), default_len);
            assert!(output.ring_program_id.is_none());
            assert!(ring_confidential_encrypted_output_body(data).is_none());
        }
    }

    #[test]
    fn full_withdrawal_padding_uses_the_canonical_empty_payload_size() {
        let outputs = (0..2)
            .map(|index| SppProofOutputUtxo {
                blinding: random_blinding(),
                ring_program_id: (index % 2 == 0).then_some(ring().program_id()),
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let mut encoded = outputs
            .iter()
            .map(|output| TransactOutput {
                utxo_hash: output.hash(0).unwrap(),
                owner_tag: OwnerTag::Inline([0; 32]),
                data: None,
            })
            .collect::<Vec<_>>();
        frame_dummy_outputs(&outputs, &mut encoded).unwrap();
        for (output, encoded) in outputs.iter().zip(&encoded) {
            assert!(output.is_dummy());
            let data = encoded.data.as_deref().unwrap();
            let body = if output.ring_program_id.is_some() {
                ring_confidential_encrypted_output_body(data)
            } else {
                confidential_encrypted_output_body(data)
            }
            .unwrap();
            let key_len = ViewingKey::new().pubkey().as_bytes().len();
            let plaintext = ConfidentialOutputPlaintext {
                asset_id: zolana_transaction::SOL_ASSET_ID,
                amount: 0,
                blinding: [0; 32],
                ring_program_id: output.ring_program_id,
                data: Data::default(),
            }
            .serialize()
            .unwrap();
            assert_eq!(body.len(), key_len + plaintext.len());
        }
    }

    #[test]
    fn a_record_carrier_frames_a_full_withdrawals_dummy_outputs() {
        let mut proof = framed_fixture(&[Some(ring().program_id()); 3]);
        let money_count = proof.output_utxos.len() - 1;
        for output in &mut proof.output_utxos[..money_count] {
            output.owner_address = None;
        }
        let record = proof.external_data.outputs.last().unwrap().clone();
        frame_dummy_outputs(&proof.output_utxos, &mut proof.external_data.outputs).unwrap();
        assert_eq!(proof.external_data.outputs.last(), Some(&record));
        assert!(proof.output_utxos[..money_count]
            .iter()
            .all(SppProofOutputUtxo::is_dummy));
        for encoded in &proof.external_data.outputs[..money_count] {
            let data = encoded.data.as_deref().unwrap();
            assert!(ring_confidential_encrypted_output_body(data).is_some());
            assert_eq!(data.len(), record.data.as_ref().unwrap().len());
        }
    }

    #[test]
    fn dummy_framing_matches_ring_slot_lengths() {
        let mut proof_inputs = framed_fixture(&[Some(ring().program_id()); 3]);
        proof_inputs.output_utxos[1].owner_address = None;
        proof_inputs.output_utxos[2].owner_address = None;
        assert!(
            proof_inputs
                .output_utxos
                .iter()
                .filter(|output| output.is_dummy())
                .count()
                >= 2
        );
        let real_len = proof_inputs
            .output_utxos
            .iter()
            .zip(&proof_inputs.external_data.outputs)
            .find(|(output, _)| !output.is_dummy())
            .and_then(|(_, output)| output.data.as_ref().map(Vec::len))
            .expect("real output data");
        frame_dummy_outputs(
            &proof_inputs.output_utxos,
            &mut proof_inputs.external_data.outputs,
        )
        .expect("dummy framing");
        let lengths = proof_inputs
            .external_data
            .outputs
            .iter()
            .map(|output| output.data.as_ref().expect("output data").len())
            .collect::<Vec<_>>();
        assert!(proof_inputs.external_data.outputs.iter().all(|output| {
            output
                .data
                .as_deref()
                .and_then(ring_confidential_encrypted_output_body)
                .is_some()
        }));
        assert!(lengths.iter().all(|length| *length == real_len));
        let dummy_keys = proof_inputs
            .output_utxos
            .iter()
            .zip(&proof_inputs.external_data.outputs)
            .filter(|(output, _)| output.is_dummy())
            .map(|(_, output)| {
                let body = ring_confidential_encrypted_output_body(
                    output.data.as_deref().expect("dummy output data"),
                )
                .expect("dummy confidential body");
                body[..33].to_vec()
            })
            .collect::<Vec<_>>();
        assert_ne!(dummy_keys[0], dummy_keys[1]);
    }
}
