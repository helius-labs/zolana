use core::future::Future;

use custom_ring_interface::PolicyConfig;
use futures::future::try_join;
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
    input_utxos,
    prover::{Delivery, ProveRequest},
    AsyncProverClient, AsyncRpc, ClientError, ComputeBudgetConfig, MerkleProof, NonInclusionProof,
    Proof, ProofCompressed, ProverClient, RingTransferProofResult, RingTransferProver, Rpc,
    SettlementAccountValidation, Shape, SpendProof, SppProofInputUtxo, SppProofInputs,
    TransferInputs, TransferSpendInput,
};
use zolana_interface::event::OutputDataEncoding;
use zolana_interface::{
    instruction::{
        tag::RING_TRANSACT, CircuitId, DepositAsset, DepositBuildError, RingAssetDeposit,
        TransactInterfaceTransferAccounts, TransactIxData, TransactOutput, TransactProof,
    },
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{
    random_blinding, random_salt, KeypairError, P256Pubkey, ShieldedAddress, ShieldedKeypair,
    ViewingKey, ViewingKeyTrait,
};
use zolana_ring_policy::{ListNamespace, Member, VelocityMode, VelocityRow};
use zolana_transaction::{
    instructions::transact::{
        encode_confidential_slots, ChangeLayout, ExternalData, PreparedTransfer, SppProofOutputUtxo,
    },
    owner_utxo_hash,
    serialization::confidential::ConfidentialOutputPlaintext,
    AssetRegistry, Data, EncryptedScheme, RingDepositPlaintext, TransactionError, Utxo,
};
use zolana_tree::{TreeAccount, TreeError};

use crate::{
    head_map::HeadWitness,
    instructions::{
        spend::{ReadEnvironment, ReadSpendRecord},
        transact::{
            request::json_body, CustomRingPolicyProofRequestJson, HeadTransitionJson, ProvedWindow,
            RingIdentity, VelocityProofInput,
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
    sender: &'a (dyn ViewingKeyTrait + Send + Sync),
    prepared: PreparedTransfer,
    interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    input_tree: Option<Address>,
    output_tree: Option<Address>,
    assets: Option<&'a AssetRegistry>,
    cosigner: Option<Address>,
}

pub struct CustomRingTransferInput<'a> {
    pub ring: CustomRing,
    /// The sender's viewing key. Only [`ViewingKeyTrait::get_transaction_viewing_key`]
    /// is used, so a backend that keeps the owner's signing key elsewhere -- an
    /// HSM, or a remote custodian -- can build a transfer. The owner's signature
    /// is not taken here: [`ProvenTransfer`] reports `owner_signers`, and the
    /// owner signs the assembled Solana transaction.
    ///
    /// `ShieldedKeypair` implements the trait, so passing one still works.
    ///
    /// `Send + Sync` so that [`Self::prove_async`]'s future is `Send`. Without
    /// it the async path cannot be awaited on a multi-threaded runtime, which
    /// is exactly where a host that needs the async path runs.
    pub sender: &'a (dyn ViewingKeyTrait + Send + Sync),
    pub prepared: PreparedTransfer,
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
    pub cosigner: Option<Address>,
    /// The velocity statement demands the co-signer, the caller must sign with it.
    pub approval_required: bool,
    pub head_transition: Option<custom_ring_interface::HeadMapTransition>,
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
    #[error("transfer was prepared with padded change slots, prepare it with ConfidentialTransfer::with_compact_change")]
    PaddedChange,
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
            prepared: input.prepared,
            interface_transfer_accounts: Vec::new(),
            input_tree: None,
            output_tree: None,
            assets: None,
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
    pub fn with_assets(mut self, assets: &'a AssetRegistry) -> Self {
        self.assets = Some(assets);
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
                spends: &staged.proof_inputs.input_utxos,
            }
            .load()?,
            allow_dummy_inputs: input_tree.allow_dummy_inputs,
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
                spends: &staged.proof_inputs.input_utxos,
            }
            .load_async()
            .await?,
            allow_dummy_inputs: input_tree.allow_dummy_inputs,
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
                let entries_tree = pinned.config.entries_tree;
                if self.input_tree != Some(entries_tree)
                    || self.output_tree.unwrap_or(entries_tree) != entries_tree
                {
                    return Err(TransferError::EntriesTreeRequired { entries_tree });
                }
                Ok(SpendLimit::PerWindow(Box::new(VelocityLookup {
                    read: ReadSpendRecord {
                        ring: self.ring,
                        entries_tree,
                        entries_tree_id: pinned.config.entries_tree_id(),
                        member: sender_member(&self.prepared.owner)?,
                    },
                    context: VelocityContext {
                        namespace: self.ring.namespace_pda(),
                        owner: ListNamespace {
                            owner_hash: pinned.config.namespace_owner_hash,
                        },
                        identity,
                        entries_tree_id: pinned.config.entries_tree_id(),
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
        let assets = self.assets.ok_or(TransferError::MissingAssetRegistry)?;
        // A padded change slot overflows the packet and cannot be opened by the auditor.
        if self.prepared.change_layout() != ChangeLayout::Compact {
            return Err(TransferError::PaddedChange);
        }
        let mut prepared = self.prepared;
        let program_id = self.ring.program_id();
        RingMembership {
            program_id,
            inputs: &prepared.inputs,
            outputs: &prepared.outputs,
        }
        .validate()?;
        validate_transfer_accounts(&prepared, &self.interface_transfer_accounts)?;
        let payer = prepared.payer;
        let tx_viewing_key = self
            .sender
            .get_transaction_viewing_key(&prepared.first_nullifier)?;
        let salt = random_salt();
        let stage = match limit {
            SpendLimit::Unbounded => VelocityStage {
                plan: None,
                proof_input: None,
                head: None,
            },
            SpendLimit::PerTransfer { rows, identity } => {
                let outflows = Outflows {
                    sender: sender_member(&prepared.owner)?,
                    ring: program_id,
                    inputs: &prepared.inputs,
                    outputs: &prepared.outputs,
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
                        sender: sender_member(&prepared.owner)?,
                        ring: program_id,
                        inputs: &prepared.inputs,
                        outputs: &prepared.outputs,
                    },
                    tx_viewing_key: &tx_viewing_key,
                    salt,
                    first_nullifier: prepared.first_nullifier,
                    output_blinding_seed: prepared.output_blinding_seed()?,
                    money_shape: prepared.shape,
                }
                .plan()?;
                append_record_slots(&mut prepared, &plan)?;
                VelocityStage {
                    proof_input: Some(plan.proof_input),
                    head: Some(CompressedHead {
                        witness: facts.head.clone(),
                        transition: plan.head_transition,
                    }),
                    plan: Some(plan),
                }
            }
        };

        // ORDER MATTERS. The auditor message has to be inside `external_data`
        // BEFORE the SPP proof runs: SPP folds `messages` into
        // `external_data_hash` and that into `private_tx_hash`, which is element 1
        // of the custom-ring circuit's public-input chain. Proving SPP first and
        // appending the message afterwards yields two irreconcilable
        // `private_tx_hash` values -- whichever one the ring proof commits to, the
        // other is the one SPP checks. `encrypt` returning a `PendingCustomRingProof`
        // that only `finish` can turn into a witness is what makes the order
        // unforgettable: there is no `private_tx_hash` to supply yet.
        let EncryptedAudit {
            pending: pending_proof,
            message: auditor_message,
        } = CustomRingProofParams {
            tx_viewing_key: tx_viewing_key.clone(),
            auditor_pk,
        }
        .encrypt()?;
        let slots = encode_confidential_slots(&prepared.outputs, assets, &tx_viewing_key, salt)?;
        let mut messages = Vec::with_capacity(3);
        if let Some(plan) = stage.plan {
            messages.push(plan.record_message);
            messages.push(plan.counters_message);
        }
        let mut proof_inputs = prepared.finalize(tx_viewing_key.pubkey(), salt, slots)?;
        frame_dummy_outputs(
            &proof_inputs.output_utxos,
            &mut proof_inputs.external_data.outputs,
        )?;
        messages.push(auditor_message.to_message_data(&auditor_pk));
        proof_inputs.external_data.messages = messages;
        // RING_TRANSACT is folded into external_data_hash and from there into
        // private_tx_hash, so it must be bound before anything hashes external data.
        proof_inputs.external_data.instruction_discriminator = RING_TRANSACT;

        let head_map_root = stage.head.is_some().then(|| self.ring.head_map_root_pda());
        Ok(StagedTransfer {
            head_witness: stage.head,
            tx_viewing_key,
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
fn append_record_slots(
    prepared: &mut PreparedTransfer,
    plan: &VelocityPlan,
) -> Result<(), TransferError> {
    let output_seed = prepared.output_blinding_seed()?;
    while prepared.inputs.len() + 1 < plan.shape.n_inputs() {
        prepared.inputs.push(
            zolana_transaction::instructions::types::SppProofInputUtxo::new_dummy()
                .in_tree(plan.input.tree_id),
        );
    }
    while prepared.outputs.len() + 1 < plan.shape.n_outputs() {
        let index = u32::try_from(prepared.outputs.len())
            .map_err(|_| TransferError::PolicyShapeUnsupported)?;
        prepared.outputs.push(SppProofOutputUtxo {
            blinding: zolana_transaction::utxo::derive_transact_output_blinding(
                &prepared.first_nullifier,
                &output_seed,
                index,
            )?,
            owner_tag: Some(prepared.owner.signing_pubkey.confidential_view_tag()?),
            ..Default::default()
        });
    }
    prepared.inputs.push(plan.input.clone());
    prepared.outputs.push(plan.output.clone());
    prepared.shape = plan.shape;
    Ok(())
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
                    && self.output_tree_id != pinned.config.entries_tree_id()
                {
                    return Err(TransferError::TreeIdMismatch {
                        tree: pinned.config.entries_tree,
                        expected: pinned.config.entries_tree_id(),
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
            entries_tree: config.entries_tree,
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
        let ring_result = RingTransferProver {
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
            shape: Some(Shape::new(tx_shape.n_inputs(), tx_shape.n_outputs())),
        }
        .build()?;
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
        kind: PolicyProofKind,
    },
}

pub(crate) struct CompressedHead {
    pub witness: HeadWitness,
    pub transition: custom_ring_interface::HeadMapTransition,
}

pub(crate) enum PolicyProofKind {
    Ordinary,
    Compressed(CompressedHead),
    Delegate,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WrappedPolicyJson {
    circuit_type: &'static str,
    policy: CustomRingPolicyProofRequestJson,
}

#[derive(Serialize)]
struct CompressedPolicyJson {
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
        *kind = PolicyProofKind::Compressed(head);
        Ok(self)
    }

    pub(crate) fn for_delegate(mut self) -> Self {
        if let Self::Policy { kind, .. } = &mut self {
            *kind = PolicyProofKind::Delegate;
        }
        self
    }

    pub fn proven(self, proof: Proof) -> Result<TierProof, TransferError> {
        let proof = to_instruction_proof(proof)?;
        Ok(match self {
            Self::Base(_) => TierProof::Base(proof),
            Self::Policy {
                entries_tree,
                roots,
                approval_required,
                kind,
                ..
            } => TierProof::Policy {
                proof,
                entries_tree,
                roots,
                approval_required,
                head_transition: match kind {
                    PolicyProofKind::Compressed(head) => Some(head.transition),
                    _ => None,
                },
            },
        })
    }
}

/// The tier's proof in the instruction's wire encoding.
pub(crate) enum TierProof {
    Base(CustomRingProof),
    Policy {
        proof: CustomRingProof,
        entries_tree: Address,
        roots: TransactRoots,
        approval_required: bool,
        head_transition: Option<custom_ring_interface::HeadMapTransition>,
    },
}

pub(crate) struct TierBinding {
    pub proof: CustomRingProof,
    pub entries_tree: Option<Address>,
    pub state_root_index: u16,
    pub nullifier_root_index: u16,
    pub approval_required: bool,
    pub head_transition: Option<custom_ring_interface::HeadMapTransition>,
}

impl TierProof {
    pub fn binding(self) -> TierBinding {
        match self {
            Self::Base(proof) => TierBinding {
                proof,
                entries_tree: None,
                state_root_index: 0,
                nullifier_root_index: 0,
                approval_required: false,
                head_transition: None,
            },
            Self::Policy {
                proof,
                entries_tree,
                roots,
                approval_required,
                head_transition,
            } => TierBinding {
                proof,
                entries_tree: Some(entries_tree),
                state_root_index: roots.state_index,
                nullifier_root_index: roots.nullifier_index,
                approval_required,
                head_transition,
            },
        }
    }
}

/// Both witnesses built and the auditor encryption closed over the transfer's
/// `private_tx_hash`. Only the two proofs are outstanding.
struct WitnessedTransfer {
    request: TierRequest,
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
            head_transition,
        } = self.request.proven(ring_proof)?.binding();
        let n_inputs = self.proof_inputs.check_shape()?.n_inputs();
        Ok(ProvenTransfer {
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
            head_transition: self.head_transition,
        }
        .instruction()
        .map_err(Into::into)
    }
}

impl RingDeposit<'_> {
    pub fn send<R: Rpc>(self, rpc: &R) -> Result<RingDepositReceipt, DepositError> {
        let blinding = random_blinding();
        let deposit = RingAssetDeposit {
            asset: self.asset,
            view_tag: self.recipient.recipient_bootstrap_view_tag(),
            owner_utxo_hash: owner_utxo_hash(&self.recipient.owner_hash()?, &blinding)?,
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
        let has_policy = self
            .ring
            .read_config(rpc)?
            .ok_or(DepositError::MissingRingConfig)?
            .has_policy;
        let ix = Deposit {
            ring: self.ring,
            tree: self.tree,
            depositor: self.payer.pubkey(),
            deposits: vec![deposit],
            cosigner: self.cosigner.map(Signer::pubkey),
            has_policy,
        }
        .instruction()?;
        let mut signers = vec![self.payer];
        signers.extend(self.cosigner);
        let signature = rpc.create_and_send_transaction(
            core::slice::from_ref(&ix),
            self.payer.pubkey(),
            &signers,
            ComputeBudgetConfig::for_instruction_count(1),
        )?;
        Ok(RingDepositReceipt {
            signature,
            utxo: Utxo {
                owner: self.recipient.signing_pubkey(),
                asset: self.asset.mint(),
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
    pub allow_dummy_inputs: bool,
    pub tree: BoundTree,
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
    let mut tree_account = TreeAccount::from_bytes(&mut account.data, tree.to_bytes())?;
    Ok(TreeState {
        allow_dummy_inputs: tree_account.allow_dummy_inputs()?,
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
    prepared: &PreparedTransfer,
    accounts: &[TransactInterfaceTransferAccounts],
) -> Result<(), TransferError> {
    let transfers = prepared
        .interface_transfers
        .iter()
        .copied()
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
    pub inputs: Vec<TransferSpendInput>,
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
    pub spends: &'a [SppProofInputUtxo],
}

impl<'a, I> RingSpendInputs<'a, I> {
    /// The hashes to prove inclusion for, and the nullifiers to prove absence
    /// of. Independent of transport.
    fn queries(&self) -> Result<SpendQueries, TransferError> {
        let utxo_hashes = self
            .spends
            .iter()
            .filter(|spend| !spend.is_dummy())
            .map(SppProofInputUtxo::hash)
            .collect::<Result<Vec<_>, _>>()?;
        let nullifiers = self
            .spends
            .iter()
            .map(SppProofInputUtxo::nullifier)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SpendQueries {
            utxo_hashes,
            nullifiers,
        })
    }
}

impl<I: AsyncRpc> RingSpendInputs<'_, I> {
    pub async fn load_async(self) -> Result<Vec<TransferSpendInput>, TransferError> {
        let SpendQueries {
            utxo_hashes,
            nullifiers,
        } = self.queries()?;
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
    pub fn load(self) -> Result<Vec<TransferSpendInput>, TransferError> {
        let SpendQueries {
            utxo_hashes,
            nullifiers,
        } = self.queries()?;
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
    ) -> Result<Vec<TransferSpendInput>, TransferError> {
        let real_count = self.spends.iter().filter(|spend| !spend.is_dummy()).count();
        if states.len() != real_count || non_inclusions.len() != self.spends.len() {
            return Err(TransferError::IncompleteProofSet);
        }
        let mut states = states.into_iter();
        self.spends
            .iter()
            .zip(non_inclusions)
            .map(|(spend, nullifier)| {
                let (proof, nullifier_proof) = if spend.is_dummy() {
                    (None, Some(nullifier))
                } else {
                    let state = states.next().ok_or(TransferError::IncompleteProofSet)?;
                    (Some(SpendProof { state, nullifier }), None)
                };
                Ok(TransferSpendInput {
                    utxo: spend.utxo.clone(),
                    nullifier_key: spend.nullifier_key.clone(),
                    data_hash: spend.data_hash,
                    ring_data_hash: spend.ring_data_hash,
                    tree_id: spend.tree_id,
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
        let inputs = input_utxos(self.nullifiers, self.input_tree_indexes)?;
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
    use zolana_transaction::instructions::transact::{ConfidentialTransfer, SettlementTarget};
    use zolana_transaction::SOL_MINT;

    use super::*;

    fn ring() -> CustomRing {
        CustomRing::new(Address::new_from_array([42u8; 32]))
    }

    #[test]
    fn spend_proofs_carry_the_note_data_hashes() {
        let owner = ShieldedKeypair::new_ed25519().expect("owner");
        let spends = [SppProofInputUtxo {
            utxo: Utxo {
                owner: owner.signing_pubkey(),
                asset: SOL_MINT,
                amount: 5,
                blinding: [1u8; 32],
                ring_program_id: None,
                data: Data::default(),
            },
            nullifier_key: owner.nullifier_key.clone(),
            data_hash: Some([7u8; 32]),
            ring_data_hash: Some([8u8; 32]),
            // TODO(tree-id): resolve the tree id from the tree account.
            tree_id: 0,
        }];
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
            spends: &spends,
        }
        .assemble(vec![merkle], vec![non_inclusion])
        .expect("one real spend pairs with its proofs");
        assert_eq!(inputs[0].data_hash, Some([7u8; 32]));
        assert_eq!(inputs[0].ring_data_hash, Some([8u8; 32]));
    }

    fn prepared_transfer(amount: u64) -> (ShieldedKeypair, PreparedTransfer) {
        let sender = ShieldedKeypair::new_ed25519().expect("sender");
        let recipient = ShieldedKeypair::new_ed25519().expect("recipient");
        let input = SppProofInputUtxo::new(
            Utxo {
                owner: sender.signing_pubkey(),
                asset: SOL_MINT,
                amount: 10,
                blinding: random_blinding(),
                ring_program_id: Some(ring().program_id()),
                data: Data::default(),
            },
            &sender,
        );
        let mut transfer = ConfidentialTransfer::new(
            sender.shielded_address().expect("sender address"),
            vec![input],
            solana_signer::Signer::pubkey(&sender),
        );
        transfer
            .send(
                &recipient.shielded_address().expect("recipient address"),
                SOL_MINT,
                amount,
            )
            .expect("recipient");
        (sender, transfer.prepare().expect("prepared transfer"))
    }

    #[test]
    fn membership_accepts_active_and_default_outputs() {
        let (_sender, mut prepared) = prepared_transfer(4);
        RingMembership {
            program_id: ring().program_id(),
            inputs: &prepared.inputs,
            outputs: &prepared.outputs,
        }
        .validate()
        .expect("default outputs");
        prepared.outputs[1].ring_program_id = Some(ring().program_id());
        RingMembership {
            program_id: ring().program_id(),
            inputs: &prepared.inputs,
            outputs: &prepared.outputs,
        }
        .validate()
        .expect("active ring output");
        prepared.outputs[1].ring_program_id = Some(Address::new_from_array([9u8; 32]));
        assert!(matches!(
            RingMembership {
                program_id: ring().program_id(),
                inputs: &prepared.inputs,
                outputs: &prepared.outputs,
            }
            .validate(),
            Err(TransferError::ForeignRing(_))
        ));
    }

    #[test]
    fn membership_refuses_ring_data_outside_a_ring() {
        let (_sender, mut prepared) = prepared_transfer(4);
        prepared.outputs[1].ring_data_hash = Some([3u8; 32]);
        assert!(matches!(
            RingMembership {
                program_id: ring().program_id(),
                inputs: &prepared.inputs,
                outputs: &prepared.outputs,
            }
            .validate(),
            Err(TransferError::RingDataOutsideRing)
        ));
        prepared.outputs[1].ring_program_id = Some(ring().program_id());
        RingMembership {
            program_id: ring().program_id(),
            inputs: &prepared.inputs,
            outputs: &prepared.outputs,
        }
        .validate()
        .expect("ring data inside the ring");
    }

    #[test]
    fn withdrawal_accounts_are_validated_before_proving() {
        let (sender, _) = prepared_transfer(4);
        let input = SppProofInputUtxo::new(
            Utxo {
                owner: sender.signing_pubkey(),
                asset: SOL_MINT,
                amount: 10,
                blinding: random_blinding(),
                ring_program_id: Some(ring().program_id()),
                data: Data::default(),
            },
            &sender,
        );
        let recipient = Address::new_from_array([7u8; 32]);
        let mut transfer = ConfidentialTransfer::new(
            sender.shielded_address().expect("sender address"),
            vec![input],
            solana_signer::Signer::pubkey(&sender),
        );
        transfer
            .withdraw(
                SOL_MINT,
                4,
                SettlementTarget::Sol {
                    user_sol_account: recipient,
                },
            )
            .expect("withdrawal");
        let prepared = transfer.prepare().expect("prepared withdrawal");
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
                prepared,
            })
            .prove_async(AsyncTransferProofEnvironment {
                indexer: &rpc,
                rpc: &rpc,
                prover: &prover,
            }),
        );
    }

    #[test]
    fn a_viewing_key_alone_can_build_a_transfer() {
        // The sender is used only to derive the transaction viewing key. The
        // owner's signature is taken later, over the assembled Solana
        // transaction, from the `owner_signers` a `ProvenTransfer` reports. So a
        // backend that keeps the signing key elsewhere -- an HSM, or a remote
        // custodian holding it in an enclave -- can still build the transfer.
        // This test exists to keep that true: narrowing `sender` back to
        // `&ShieldedKeypair` would stop it compiling.
        let (keypair, prepared) = prepared_transfer(4);
        let first_nullifier = prepared.first_nullifier;
        let viewing_key: &ViewingKey = &keypair.viewing_key;

        let transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring: ring(),
            sender: viewing_key,
            prepared,
        });

        // The viewing key alone derives the same per-transaction key the full
        // keypair would, so the built transfer is not merely well-typed.
        assert_eq!(
            transfer
                .sender
                .get_transaction_viewing_key(&first_nullifier)
                .expect("transaction viewing key from the viewing key alone")
                .pubkey(),
            keypair
                .get_transaction_viewing_key(&first_nullifier)
                .expect("transaction viewing key from the keypair")
                .pubkey(),
        );
    }

    #[test]
    fn output_framing_selects_ring_membership() {
        let (sender, mut prepared) = prepared_transfer(4);
        let tx_viewing_key = sender
            .get_transaction_viewing_key(&prepared.first_nullifier)
            .expect("transaction viewing key");
        let salt = random_salt();
        let default_slots = encode_confidential_slots(
            &prepared.outputs,
            &AssetRegistry::default(),
            &tx_viewing_key,
            salt,
        )
        .expect("default slots");
        assert!(default_slots.iter().flatten().all(|slot| {
            confidential_encrypted_output_body(&slot.data).is_some()
                && ring_confidential_encrypted_output_body(&slot.data).is_none()
        }));

        for output in &mut prepared.outputs {
            output.ring_program_id = Some(ring().program_id());
        }
        let ring_slots = encode_confidential_slots(
            &prepared.outputs,
            &AssetRegistry::default(),
            &tx_viewing_key,
            salt,
        )
        .expect("ring slots");
        assert!(ring_slots.iter().flatten().all(|slot| {
            ring_confidential_encrypted_output_body(&slot.data).is_some()
                && confidential_encrypted_output_body(&slot.data).is_none()
        }));
    }

    #[test]
    fn a_dummy_takes_the_length_of_a_real_slot_with_its_own_binding() {
        // Padded layout, the SPL change slot is a dummy, the SOL change is real.
        let (sender, mut prepared) = prepared_transfer(4);
        prepared.outputs[1].ring_program_id = Some(ring().program_id());
        let tx_viewing_key = sender
            .get_transaction_viewing_key(&prepared.first_nullifier)
            .expect("transaction viewing key");
        let salt = random_salt();
        let slots = encode_confidential_slots(
            &prepared.outputs,
            &AssetRegistry::default(),
            &tx_viewing_key,
            salt,
        )
        .expect("slots");
        let mut proof_inputs = prepared
            .finalize(tx_viewing_key.pubkey(), salt, slots)
            .expect("proof inputs");
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
        let (sender, prepared) = prepared_transfer(10);
        let payer = Address::new_from_array([99; 32]);
        let mut transfer =
            ConfidentialTransfer::new(sender.shielded_address().unwrap(), prepared.inputs, payer);
        transfer
            .withdraw(
                SOL_MINT,
                10,
                SettlementTarget::Sol {
                    user_sol_account: payer,
                },
            )
            .unwrap();
        let mut prepared = transfer.prepare().unwrap();
        let key = sender
            .get_transaction_viewing_key(&prepared.first_nullifier)
            .unwrap();
        for (index, output) in prepared.outputs.iter_mut().enumerate() {
            *output = SppProofOutputUtxo {
                ring_program_id: (index % 2 == 0).then_some(ring().program_id()),
                ..Default::default()
            };
        }
        let salt = random_salt();
        let slots = vec![None; prepared.outputs.len()];
        let mut proof = prepared.finalize(key.pubkey(), salt, slots).unwrap();
        frame_dummy_outputs(&proof.output_utxos, &mut proof.external_data.outputs).unwrap();
        for (output, encoded) in proof.output_utxos.iter().zip(&proof.external_data.outputs) {
            assert!(output.is_dummy());
            let data = encoded.data.as_deref().unwrap();
            let body = if output.ring_program_id.is_some() {
                ring_confidential_encrypted_output_body(data)
            } else {
                confidential_encrypted_output_body(data)
            }
            .unwrap();
            let plaintext = ConfidentialOutputPlaintext {
                asset_id: zolana_transaction::SOL_ASSET_ID,
                amount: 0,
                blinding: [0; 32],
                ring_program_id: output.ring_program_id,
                data: Data::default(),
            }
            .serialize()
            .unwrap();
            assert_eq!(body.len(), key.pubkey().as_bytes().len() + plaintext.len());
        }
    }

    #[test]
    fn a_record_carrier_frames_a_full_withdrawals_dummy_outputs() {
        let (sender, mut prepared) = prepared_transfer(10);
        let key = sender
            .get_transaction_viewing_key(&prepared.first_nullifier)
            .unwrap();
        for output in &mut prepared.outputs {
            *output = SppProofOutputUtxo::default().with_ring_program_id(ring().program_id());
        }
        let namespace = ring().namespace_pda();
        *prepared.outputs.last_mut().unwrap() = SppProofOutputUtxo {
            asset: SOL_MINT,
            blinding: random_blinding(),
            data_hash: Some([1; 32]),
            owner_address: Some(zolana_keypair::ShieldedAddress::for_pda(
                &namespace,
                zolana_keypair::NullifierKey::from_secret([0; 31])
                    .pubkey()
                    .unwrap(),
                key.pubkey(),
            )),
            owner_tag: Some(namespace.to_bytes()),
            ..Default::default()
        };
        let salt = random_salt();
        let slots =
            encode_confidential_slots(&prepared.outputs, &AssetRegistry::default(), &key, salt)
                .unwrap();
        let mut proof = prepared.finalize(key.pubkey(), salt, slots).unwrap();
        let record = proof.external_data.outputs.last().unwrap().clone();
        frame_dummy_outputs(&proof.output_utxos, &mut proof.external_data.outputs).unwrap();
        assert_eq!(proof.external_data.outputs.last(), Some(&record));
        let money_count = proof.output_utxos.len() - 1;
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
        let (sender, mut prepared) = prepared_transfer(10);
        for output in &mut prepared.outputs {
            output.ring_program_id = Some(ring().program_id());
        }
        let tx_viewing_key = sender
            .get_transaction_viewing_key(&prepared.first_nullifier)
            .expect("transaction viewing key");
        let salt = random_salt();
        let slots = encode_confidential_slots(
            &prepared.outputs,
            &AssetRegistry::default(),
            &tx_viewing_key,
            salt,
        )
        .expect("slots");
        let mut proof_inputs = prepared
            .finalize(tx_viewing_key.pubkey(), salt, slots)
            .expect("proof inputs");
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
