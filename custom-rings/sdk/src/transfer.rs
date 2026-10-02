#[cfg(feature = "solana-rpc")]
use crate::instructions::transact::ProvedWindow;
use core::future::Future;

use custom_ring_interface::PolicyConfig;
use custom_ring_interface::{RingDepositAuditCapsule, MAX_RING_DEPOSIT_AUDIT_SLOTS};
use futures::future::try_join;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::Serialize;
use solana_account::Account;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_signature::Signature;
use solana_signer::Signer;
use thiserror::Error;
use zeroize::Zeroizing;
use zolana_client::prover::indexed::{
    IndexedTransferPreparation, IndexedTransferRail, PreparedIndexedTransfer, ProofDataSource,
};
use zolana_client::{
    input_utxos_from_nullifiers,
    prover::{Delivery, ExpectedProvingKey, ProveRequest},
    AsyncProverClient, AsyncRpc, ClientError, ComputeBudgetConfig, MerkleProof, NonInclusionProof,
    Proof, ProofAuthority, ProofCompressed, ProofInputUtxo, Prover, ProverClient, ProverExt,
    RingTransferProofResult, RingTransferProver, Rpc, SettlementAccountValidation, SpendProof,
    TransferInputUtxo,
};
use zolana_interface::{
    instruction::{
        tag::RING_TRANSACT, CircuitId, OwnerTag, TransactIxData, TransactOutput, TransactProof,
    },
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    MAX_INPUT_TREES, N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{
    random_blinding, KeypairError, NullifierKey, P256Pubkey, ShieldedAddress, ShieldedKeypair,
    ViewingKey,
};
use zolana_program::instruction::{
    DepositAsset, DepositBuildError, RingAssetDeposit, TransactInterfaceTransferAccounts,
};
use zolana_ring_client::{DepositEncryption, DepositOpening, DepositSeal};
use zolana_ring_policy::{ListNamespace, Member, VelocityMode, VelocityRow};
use zolana_transaction::{
    instructions::transact::{
        frame_dummy_outputs, seal_output, ConfidentialTransaction, ExternalData, ResolvedOwnerTag,
        SppProofInputs, SppProofOutputUtxo,
    },
    keys::{ShieldedKeys, TransactionKeyRequest},
    owner_utxo_hash,
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding, SppProofInputUtxo},
    Data, Mint, RingDepositPlaintext, TransactionError, Utxo,
};
use zolana_tree::{TreeAccount, TreeError};

use crate::{
    escrow::{EscrowedKeys, KeyRegistry, OutputKey, RegistryKeyOpening},
    instructions::{
        entry::zero_nullifier_key,
        spend::{ReadEnvironment, ReadSpendRecord},
        transact::{
            request::json_body, CustomRingPolicyProofRequestJson, EscrowBinding, PolicyReads,
            RingIdentity, TransactInstructionError, VelocityProofInput,
        },
    },
    to_instruction_proof,
    velocity::{
        ChargeRows, MoneySlots, Outflows, VelocityContext, VelocityFacts, VelocityPlan,
        VelocityPlanInput,
    },
    witness::{list_entry, CustomRingWitness, CustomRingWitnessInput},
    AccountReadError, CustomRing, CustomRingBaseProofRequest, CustomRingConfig,
    CustomRingPolicyProofRequest, CustomRingProof, CustomRingProofError, CustomRingProofInputError,
    CustomRingProofParams, CustomRingTransact, Deposit, DepositInstructionError, EncryptedAudit,
    KeyRegistrationError, PendingCustomRingProof, PinnedPolicy, PolicyMatchError, PoolTree,
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
    /// `None` on an audit-only ring.
    pub policy: Option<PolicyReads>,
    pub cosigner: Option<Address>,
    /// The velocity statement demands the co-signer, the caller must sign with it.
    pub approval_required: bool,
    #[cfg(feature = "solana-rpc")]
    pub(crate) window: Option<ProvedWindow>,
    payer: Address,
    trees: SpendTrees,
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

/// RPC, indexer and prover handles for deposits that require auditor disclosure.
pub struct DepositProofEnvironment<'a, I: Rpc, R: Rpc> {
    pub indexer: &'a I,
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
    Client(ClientError),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error(transparent)]
    ProofInput(#[from] CustomRingProofInputError),
    #[error(transparent)]
    Proof(#[from] CustomRingProofError),
    #[error(transparent)]
    Instruction(#[from] TransactInstructionError),
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
    #[error("the indexer proved one tree's entries against more than one root")]
    PolicyRootMismatch,
    #[error("the entries live in {count} trees, a statement reads at most {max}", max = zolana_interface::INPUT_TREES)]
    TooManyPolicyTrees { count: usize },
    #[error("no policy source serves the list")]
    MissingSourceOwner,
    #[error(transparent)]
    ListEntry(Box<crate::EntryProofError>),
    #[error("asset registry is required")]
    MissingAssetRegistry,
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
    #[error("a compressed policy statement needs a windowed policy")]
    CompressedWithoutWindow,
    #[error("the delegate moves notes on escrowed rings only")]
    DelegateRequiresEscrow,
    #[error(transparent)]
    KeyRegistration(#[from] KeyRegistrationError),
}

impl crate::projection::ProjectionLag for TransferError {
    fn is_projection_lag(&self) -> bool {
        matches!(self, Self::Client(ClientError::IndexerProofDataNotReady))
    }
}

impl From<PolicyMatchError> for TransferError {
    fn from(error: PolicyMatchError) -> Self {
        Self::PolicyMatch(Box::new(error))
    }
}

impl From<ClientError> for TransferError {
    fn from(error: ClientError) -> Self {
        match KeyRegistrationError::claim(&error) {
            Some(claimed) => Self::KeyRegistration(claimed),
            None => Self::Client(error),
        }
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
    DepositInstruction(#[from] DepositInstructionError),
    #[error(transparent)]
    Client(ClientError),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error("custom ring config does not exist")]
    MissingRingConfig,
    #[error(transparent)]
    KeyRegistration(#[from] KeyRegistrationError),
    #[cfg(feature = "solana-rpc")]
    #[error(transparent)]
    Submission(Box<crate::SubmissionError>),
    #[error("deposit {signature} failed with {error}")]
    Rejected {
        signature: Signature,
        error: solana_transaction_error::TransactionError,
    },
}

impl crate::projection::ProjectionLag for DepositError {
    fn is_projection_lag(&self) -> bool {
        matches!(self, Self::Client(ClientError::IndexerProofDataNotReady))
    }
}

impl From<ClientError> for DepositError {
    fn from(error: ClientError) -> Self {
        match KeyRegistrationError::claim(&error) {
            Some(claimed) => Self::KeyRegistration(claimed),
            None => Self::Client(error),
        }
    }
}

#[cfg(feature = "solana-rpc")]
impl From<crate::SubmissionError> for DepositError {
    fn from(error: crate::SubmissionError) -> Self {
        Self::Submission(Box::new(error))
    }
}

impl<'a> CustomRingTransfer<'a> {
    pub fn new(input: CustomRingTransferInput<'a>) -> Self {
        Self {
            ring: input.ring,
            sender: input.sender,
            nullifier_key: input.nullifier_key,
            transaction: input.transaction,
            interface_transfer_accounts: Vec::new(),
            cosigner: None,
        }
    }

    #[must_use = "use the updated transfer"]
    pub fn with_cosigner(mut self, cosigner: Address) -> Self {
        self.cosigner = Some(cosigner);
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
        crate::projection::retry_projection_lag(|| self.clone().prove_once(&environment))
    }

    fn prove_once<I: Rpc, R: Rpc>(
        self,
        environment: &TransferProofEnvironment<'_, I, R>,
    ) -> Result<ProvenTransfer, TransferError> {
        let config = self
            .ring
            .read_config(environment.rpc)?
            .ok_or(TransferError::MissingRingConfig)?;
        let key_registry = KeyRegistry::of(self.ring, &config);
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
        // The trees are read and validated first. A tree that is absent, owned by
        // another program, or not a tree account at all fails here rather than
        // after the indexer has served a full inclusion and non-inclusion proof
        // set that nothing can use.
        let trees = staged.tree_plan().read(environment.rpc)?;
        let inputs = if environment.prover.proof_data_source() == ProofDataSource::Client {
            Some(
                RingSpendInputs {
                    indexer: environment.indexer,
                    input_utxos: &staged.proof_inputs.input_utxos,
                }
                .load()?,
            )
        } else {
            None
        };
        let tier = match &policy {
            Some(policy) => Tier::Policy(staged.policy_tier(&policy.pinned, key_registry)?.build(
                environment.indexer,
                environment.rpc,
                environment.prover.proof_data_source(),
            )?),
            None => Tier::Base,
        };
        let mut witnessed = staged.witness(inputs, trees, tier)?;
        let spp_proof = witnessed
            .spp
            .prove(environment.prover, &witnessed.proof_inputs)?;
        let ring_proof = witnessed.request.prove(environment.prover)?;
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
        crate::projection::retry_projection_lag_async(|| {
            self.clone().prove_once_async(&environment)
        })
        .await
    }

    async fn prove_once_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        environment: &AsyncTransferProofEnvironment<'_, I, R>,
    ) -> Result<ProvenTransfer, TransferError> {
        let config = self
            .ring
            .read_config_async(environment.rpc)
            .await?
            .ok_or(TransferError::MissingRingConfig)?;
        let key_registry = KeyRegistry::of(self.ring, &config);
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
        // Same ordering reason as the blocking path: validate the trees before
        // asking the indexer for proofs against them.
        let trees = staged.tree_plan().read_async(environment.rpc).await?;
        let inputs = if environment.prover.proof_data_source() == ProofDataSource::Client {
            Some(
                RingSpendInputs {
                    indexer: environment.indexer,
                    input_utxos: &staged.proof_inputs.input_utxos,
                }
                .load_async()
                .await?,
            )
        } else {
            None
        };
        let tier = match &policy {
            Some(policy) => Tier::Policy(
                staged
                    .policy_tier(&policy.pinned, key_registry)?
                    .build_async(
                        environment.indexer,
                        environment.rpc,
                        environment.prover.proof_data_source(),
                    )
                    .await?,
            ),
            None => Tier::Base,
        };
        let mut witnessed = staged.witness(inputs, trees, tier)?;
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
            witnessed
                .spp
                .prove_async(environment.prover, &witnessed.proof_inputs),
            witnessed.request.prove_async(environment.prover),
        )
        .await?;
        witnessed.finish(spp, ring)
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
                Ok(SpendLimit::PerWindow(Box::new(VelocityLookup {
                    read: ReadSpendRecord {
                        ring: self.ring,
                        address_tree_id: pinned.config.address_tree_id(),
                        member: sender_member(&self.sender.address()?)?,
                    },
                    context: VelocityContext {
                        namespace: self.ring.namespace_pda(),
                        owner: ListNamespace {
                            owner_hash: pinned.config.namespace_owner_hash,
                        },
                        identity,
                        address_tree_id: pinned.config.address_tree_id(),
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
        let transaction = self.transaction;
        if let SpendLimit::PerWindow(facts) = limit {
            check_record_tree_count(&transaction, facts.live.tree_id)?;
        }
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

        let first_nullifier = proof_inputs.first_nullifier()?;
        let output_blinding_seed =
            derive_output_blinding_seed(&first_nullifier, &proof_inputs.blinding_seed)?;
        let salt = proof_inputs.external_data.salt;
        let stage = match limit {
            SpendLimit::Unbounded => VelocityStage {
                plan: None,
                proof_input: None,
                compressed: None,
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
                    compressed: None,
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
                    money: MoneySlots::of(&proof_inputs),
                }
                .plan()?;
                RecordSlots {
                    plan: &plan,
                    tx_viewing_key: &tx_viewing_key,
                    sender_tag,
                }
                .insert(&mut proof_inputs)?;
                VelocityStage {
                    proof_input: Some(plan.proof_input),
                    compressed: Some(CompressedDisclosure {
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
        // external_data_hash includes RING_TRANSACT, so set it before anything
        // hashes the external data.
        proof_inputs.external_data.instruction_discriminator = RING_TRANSACT;

        Ok(StagedTransfer {
            compressed: stage.compressed,
            tx_viewing_key,
            nullifier_key: self.nullifier_key.cloned(),
            pending_proof,
            proof_inputs,
            payer,
            program_id,
            interface_transfer_accounts: self.interface_transfer_accounts,
            ring: self.ring,
            cosigner: self.cosigner,
            velocity: stage.proof_input,
        })
    }
}

fn check_record_tree_count(
    transaction: &ConfidentialTransaction,
    record_tree: u16,
) -> Result<(), TransferError> {
    let trees = transaction.input_tree_ids();
    let got = trees.len() + usize::from(!trees.contains(&record_tree));
    if got > MAX_INPUT_TREES {
        return Err(TransactionError::TooManyInputTrees {
            got,
            max: MAX_INPUT_TREES,
        }
        .into());
    }
    Ok(())
}

pub(crate) use custom_ring_interface::{RECORD_INPUT_SLOT, RECORD_OUTPUT_SLOT};

/// Inputs become `[money0, record, money.., dummies]`. The dummies take
/// money0's tree, so the public tree pattern reveals neither the record nor
/// the real input count.
fn place_record_input(
    inputs: &mut Vec<SppProofInputUtxo>,
    record: SppProofInputUtxo,
    n_inputs: usize,
) -> Result<(), TransferError> {
    inputs.retain(|input| !input.is_dummy());
    let padding_tree = inputs.first().ok_or(TransactionError::NoInputs)?.tree_id;
    if inputs.len() + 1 > n_inputs {
        return Err(TransferError::PolicyShapeUnsupported);
    }
    inputs.insert(RECORD_INPUT_SLOT, record);
    while inputs.len() < n_inputs {
        inputs.push(SppProofInputUtxo::dummy(padding_tree)?);
    }
    Ok(())
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
    compressed: Option<CompressedDisclosure>,
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
        let live = self
            .read
            .read_current(env)
            .map_err(list_entry)?
            .ok_or(TransferError::SpendRecordMissing)?;
        self.context.facts(live, env.rpc.get_slot()?)
    }

    async fn read_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        env: ReadEnvironment<'_, I, R>,
    ) -> Result<VelocityFacts, TransferError> {
        let live = self
            .read
            .read_current_async(env)
            .await
            .map_err(list_entry)?
            .ok_or(TransferError::SpendRecordMissing)?;
        self.context.facts(live, env.rpc.get_slot().await?)
    }
}

/// Moves the record into its pinned slots. Outputs become `[record, money..,
/// dummies]`: every money output shifts one slot up, so it is re-blinded and
/// re-sealed for its new index, which the SPP witness derives per slot.
struct RecordSlots<'a> {
    plan: &'a VelocityPlan,
    tx_viewing_key: &'a ViewingKey,
    sender_tag: ResolvedOwnerTag,
}

impl RecordSlots<'_> {
    fn insert(self, proof_inputs: &mut SppProofInputs) -> Result<(), TransferError> {
        let Self {
            plan,
            tx_viewing_key,
            sender_tag,
        } = self;
        place_record_input(
            &mut proof_inputs.input_utxos,
            plan.input.clone(),
            plan.shape.n_inputs(),
        )?;

        let blindings = OutputBlindings::of(proof_inputs)?;
        if plan.output.blinding != blindings.at(RECORD_OUTPUT_SLOT as u32)? {
            return Err(ClientError::OutputBlindingMismatch {
                index: RECORD_OUTPUT_SLOT,
            }
            .into());
        }
        let salt = proof_inputs.external_data.salt;
        let output_tree_id = proof_inputs.output_tree_id;
        let outputs = std::mem::take(&mut proof_inputs.output_utxos);
        let encoded = std::mem::take(&mut proof_inputs.external_data.outputs);
        let resolved = std::mem::take(&mut proof_inputs.external_data.resolved_owner_tags);
        if encoded.len() != outputs.len() || resolved.len() != outputs.len() {
            return Err(TransactionError::MissingOutput.into());
        }
        let (dummies, money): (Vec<OutputSlot>, Vec<OutputSlot>) = outputs
            .into_iter()
            .zip(encoded)
            .zip(resolved)
            .map(|((output, encoded), resolved)| OutputSlot {
                output,
                encoded,
                resolved,
            })
            .partition(|slot| slot.output.is_dummy());
        let n_outputs = plan.shape.n_outputs();
        let padding = n_outputs
            .checked_sub(money.len() + 1)
            .ok_or(TransferError::PolicyShapeUnsupported)?;
        let dummy = dummies
            .last()
            .map(OutputSlot::dummy_like)
            .unwrap_or_else(|| {
                OutputSlot::dummy(
                    sender_tag,
                    money.last().and_then(|slot| slot.output.ring_program_id),
                )
            });
        let mut dummies = dummies;
        dummies.resize_with(padding, || dummy.clone());

        let record_tag = plan
            .output
            .owner_address
            .ok_or(TransactionError::OutputWithoutOwner {
                slot_index: RECORD_OUTPUT_SLOT,
            })?
            .signing_pubkey
            .confidential_view_tag()?;
        let record = OutputSlot {
            output: plan.output.clone(),
            encoded: TransactOutput {
                utxo_hash: [0u8; 32],
                owner_tag: OwnerTag::Inline(record_tag),
                data: None,
            },
            resolved: record_tag,
        };
        for (index, mut slot) in std::iter::once(record)
            .chain(money)
            .chain(dummies)
            .enumerate()
        {
            let slot_index =
                u32::try_from(index).map_err(|_| TransferError::PolicyShapeUnsupported)?;
            slot.output.blinding = blindings.at(slot_index)?;
            if !slot.output.is_dummy() {
                let sealed = seal_output(&slot.output, slot_index, tx_viewing_key, salt)?
                    .ok_or(TransactionError::OutputWithoutOwner { slot_index: index })?;
                slot.encoded.data = Some(sealed.data);
            }
            slot.encoded.utxo_hash = slot.output.hash(output_tree_id)?;
            proof_inputs.output_utxos.push(slot.output);
            proof_inputs.external_data.outputs.push(slot.encoded);
            proof_inputs
                .external_data
                .resolved_owner_tags
                .push(slot.resolved);
        }
        Ok(())
    }
}

/// One output with its published slot, kept together while slots move.
#[derive(Clone)]
struct OutputSlot {
    output: SppProofOutputUtxo,
    encoded: TransactOutput,
    resolved: [u8; 32],
}

impl OutputSlot {
    /// A fresh dummy publishing the same owner tag and ring binding as `self`.
    /// `frame_dummy_outputs` fills its ciphertext once the slots are final.
    fn dummy_like(&self) -> Self {
        Self {
            output: SppProofOutputUtxo {
                ring_program_id: self.output.ring_program_id,
                owner_tag: self.output.owner_tag,
                ..Default::default()
            },
            encoded: TransactOutput {
                utxo_hash: [0u8; 32],
                owner_tag: self.encoded.owner_tag,
                data: None,
            },
            resolved: self.resolved,
        }
    }

    /// A dummy naming the sender, encoded as the sender's real outputs are,
    /// with the ring binding of the last money slot: the change sits there
    /// when present and carries the transaction's ring.
    fn dummy(sender_tag: ResolvedOwnerTag, ring_program_id: Option<Address>) -> Self {
        Self {
            output: SppProofOutputUtxo {
                ring_program_id,
                owner_tag: Some(sender_tag.resolved),
                ..Default::default()
            },
            encoded: TransactOutput {
                utxo_hash: [0u8; 32],
                owner_tag: sender_tag.tag,
                data: None,
            },
            resolved: sender_tag.resolved,
        }
    }
}

/// Encrypts a real output for `slot_index` the way `encrypt_with_viewing_key`
/// does, with the ring scheme byte when the output is ring-bound.
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

pub(crate) struct PolicyTierInput<'a> {
    pub ring: CustomRing,
    pub inputs: &'a [SppProofInputUtxo],
    pub outputs: &'a [SppProofOutputUtxo],
    pub output_tree_id: u16,
    pub velocity: Option<VelocityProofInput>,
    pub key_registry: Option<KeyRegistry>,
}

impl PolicyTierInput<'_> {
    pub fn read<I: Rpc, R: Rpc>(
        self,
        env: ReadEnvironment<'_, I, R>,
        source: ProofDataSource,
    ) -> Result<PolicyStatement, TransferError> {
        let pinned = self
            .ring
            .read_pinned_policy(env.rpc)?
            .ok_or(TransferError::MissingPolicyConfig)?;
        self.with_config(&pinned)?
            .build(env.indexer, env.rpc, source)
    }

    pub async fn read_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        env: ReadEnvironment<'_, I, R>,
        source: ProofDataSource,
    ) -> Result<PolicyStatement, TransferError> {
        let pinned = self
            .ring
            .read_pinned_policy_async(env.rpc)
            .await?
            .ok_or(TransferError::MissingPolicyConfig)?;
        self.with_config(&pinned)?
            .build_async(env.indexer, env.rpc, source)
            .await
    }

    pub fn with_config<'s>(self, pinned: &'s PinnedPolicy) -> Result<PolicyTier<'s>, TransferError>
    where
        Self: 's,
    {
        let (velocity, committed_velocity) = match self.velocity {
            Some(velocity) => (velocity, None),
            None => {
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
                key_registry: self.key_registry,
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
    pub fn build<I: Rpc, R: Rpc>(
        self,
        indexer: &I,
        rpc: &R,
        source: ProofDataSource,
    ) -> Result<PolicyStatement, TransferError> {
        let mut witness = self.witness.build_with_source(indexer, rpc, source)?;
        if let Some(velocity) = self.committed_velocity {
            witness.velocity = velocity;
        }
        Ok(PolicyStatement::new(self.policy_config, witness))
    }

    pub async fn build_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        indexer: &I,
        rpc: &R,
        source: ProofDataSource,
    ) -> Result<PolicyStatement, TransferError> {
        let mut witness = self
            .witness
            .build_async_with_source(indexer, rpc, source)
            .await?;
        if let Some(velocity) = self.committed_velocity {
            witness.velocity = velocity;
        }
        Ok(PolicyStatement::new(self.policy_config, witness))
    }
}

/// A policy ring proves the folded statement over its policy tree roots, an
/// audit-only ring proves the audit statement alone.
pub(crate) enum Tier {
    Base,
    Policy(PolicyStatement),
}

pub(crate) struct PolicyStatement {
    policy_hash: [u8; 32],
    witness: Box<CustomRingWitness>,
}

impl PolicyStatement {
    fn new(config: &PolicyConfig, witness: CustomRingWitness) -> Self {
        Self {
            policy_hash: config.policy_hash,
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
    compressed: Option<CompressedDisclosure>,
    tx_viewing_key: ViewingKey,
    /// The sender's proof authority, which completes the built witness. Owned
    /// rather than borrowed: `stage` consumes the transfer, so the caller's
    /// reference does not outlive it.
    nullifier_key: Option<NullifierKey>,
    pending_proof: PendingCustomRingProof,
    proof_inputs: SppProofInputs,
    payer: Address,
    program_id: Address,
    interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    ring: CustomRing,
    cosigner: Option<Address>,
    velocity: Option<VelocityProofInput>,
}

impl StagedTransfer {
    fn tree_plan(&self) -> SpendTreePlan {
        SpendTreePlan::new(
            &self.proof_inputs.input_utxos,
            PoolTree::from_id(self.proof_inputs.output_tree_id),
        )
    }

    fn policy_tier<'s>(
        &'s self,
        pinned: &'s PinnedPolicy,
        key_registry: Option<KeyRegistry>,
    ) -> Result<PolicyTier<'s>, TransferError> {
        PolicyTierInput {
            ring: self.ring,
            inputs: &self.proof_inputs.input_utxos,
            outputs: &self.proof_inputs.output_utxos,
            output_tree_id: self.proof_inputs.output_tree_id,
            velocity: self.velocity,
            key_registry,
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
    fn witness(
        self,
        inputs: Option<Vec<TransferInputUtxo>>,
        trees: SpendTrees,
        tier: Tier,
    ) -> Result<WitnessedTransfer, TransferError> {
        let authority = TransferAuthority {
            owner: self.nullifier_key.as_ref(),
            spend_record: self.compressed.is_some().then_some(RECORD_INPUT_SLOT),
        };
        let spp = if let Some(inputs) = inputs {
            let tx_shape = self.proof_inputs.check_shape()?;
            let mut ring_result = RingTransferProver {
                inputs,
                outputs: self.proof_inputs.output_utxos.clone(),
                blinding_seed: self.proof_inputs.blinding_seed,
                output_tree_id: self.proof_inputs.output_tree_id,
                external_data: self.proof_inputs.external_data.clone(),
                public_transfers: self.proof_inputs.public_transfers()?,
                signer_pk_hashes: self
                    .proof_inputs
                    .signer_pk_hashes(tx_shape.signer_width())?,
                allow_dummy_inputs: trees.allow_dummy_inputs,
                ring_program_id: Some(self.program_id),
                shape: tx_shape,
            }
            .build()?;
            authority.complete_inputs(&mut ring_result.inputs.inputs)?;
            SppWitness::Complete(Box::new(ring_result))
        } else {
            SppWitness::Indexed(Box::new(
                IndexedTransferPreparation {
                    transaction: self.proof_inputs.clone(),
                    rail: IndexedTransferRail::Ring(self.program_id),
                }
                .prepare_with_dummy_policy(&authority, trees.allow_dummy_inputs)?,
            ))
        };
        let mut request = TierRequestInput {
            pending: self.pending_proof,
            private_tx_hash: spp.private_tx_hash().try_into()?,
            private_tx_blinding: self.proof_inputs.private_tx_blinding()?,
        }
        .build(tier)?;
        if let Some(compressed) = self.compressed {
            request = request.with_compressed(compressed)?;
        }
        Ok(WitnessedTransfer {
            request,
            #[cfg(feature = "solana-rpc")]
            window: self.velocity.and_then(|velocity| velocity.window()),
            tx_viewing_key: self.tx_viewing_key,
            proof_inputs: self.proof_inputs,
            spp,
            payer: self.payer,
            trees,
            interface_transfer_accounts: self.interface_transfer_accounts,
            ring: self.ring,
            cosigner: self.cosigner,
        })
    }
}

pub(crate) enum TierRequest {
    Base(CustomRingBaseProofRequest),
    Policy(PolicyRequest),
}

/// The policy prover request, with the reads the instruction binds for it.
pub(crate) struct PolicyRequest {
    request: Box<CustomRingPolicyProofRequest>,
    reads: PolicyReads,
    approval_required: bool,
    kind: PolicyProofKind,
}

pub(crate) struct CompressedDisclosure {
    pub transaction_salt: [u8; 16],
    pub counters_disclosure_hash: [u8; 32],
}

pub(crate) enum PolicyProofKind {
    Ordinary,
    Compressed(CompressedDisclosure),
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
}

impl ProveRequest for TierRequest {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        match self {
            Self::Base(request) => request.body(),
            Self::Policy(request) => request.body(),
        }
    }

    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
        match self {
            Self::Base(request) => request.proving_key(),
            Self::Policy(request) => request.proving_key(),
        }
    }

    fn delivery(&self) -> Delivery {
        match self {
            Self::Base(request) => request.delivery(),
            Self::Policy(request) => request.delivery(),
        }
    }
}

impl ProveRequest for PolicyRequest {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        match &self.kind {
            PolicyProofKind::Ordinary => self.request.body(),
            PolicyProofKind::Delegate => json_body(&WrappedPolicyJson {
                circuit_type: "custom-ring-delegate-policy",
                policy: self.request.json()?,
            }),
            PolicyProofKind::Compressed(compressed) => json_body(&CompressedPolicyJson {
                transaction_salt: crate::instructions::transact::request::bytes_to_hex(
                    &compressed.transaction_salt,
                ),
                wrapped: WrappedPolicyJson {
                    circuit_type: "custom-ring-compressed-policy",
                    policy: self.request.json()?,
                },
            }),
        }
    }

    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
        use custom_ring_interface::{
            compressed_policy_verifying_key, delegate_policy_verifying_key,
        };
        Ok(match &self.kind {
            PolicyProofKind::Ordinary => return self.request.proving_key(),
            PolicyProofKind::Delegate => ExpectedProvingKey {
                name: "custom_ring_delegate_policy.key".to_string(),
                sha256: delegate_policy_verifying_key::VERIFYINGKEY_PROVING_KEY_SHA256,
            },
            PolicyProofKind::Compressed(_) => ExpectedProvingKey {
                name: "custom_ring_compressed_policy.key".to_string(),
                sha256: compressed_policy_verifying_key::VERIFYINGKEY_PROVING_KEY_SHA256,
            },
        })
    }

    fn delivery(&self) -> Delivery {
        self.request.delivery()
    }
}

pub(crate) struct TierRequestInput {
    pub pending: PendingCustomRingProof,
    pub private_tx_hash: crate::CustomRingPrivateTxHash,
    pub private_tx_blinding: [u8; 32],
}

impl TierRequestInput {
    /// Closes the auditor encryption over the `private_tx_hash` the SPP witness fixed.
    pub(crate) fn build(self, tier: Tier) -> Result<TierRequest, TransferError> {
        Ok(match tier {
            Tier::Base => TierRequest::Base(self.pending.finish_base(self.private_tx_hash)?),
            Tier::Policy(statement) => TierRequest::Policy(self.policy(statement)?),
        })
    }

    pub(crate) fn policy(self, statement: PolicyStatement) -> Result<PolicyRequest, TransferError> {
        let PolicyStatement {
            policy_hash,
            witness,
        } = statement;
        let reads = witness.reads();
        let approval_required = witness.velocity.approval_required;
        let request = self.pending.finish(
            self.private_tx_hash,
            &self.private_tx_blinding,
            *witness,
            &policy_hash,
        )?;
        Ok(PolicyRequest {
            request: Box::new(request),
            reads,
            approval_required,
            kind: PolicyProofKind::Ordinary,
        })
    }
}

impl TierRequest {
    fn prove(&mut self, prover: &ProverClient) -> Result<Proof, ClientError> {
        match self {
            Self::Base(request) => Ok(prover.prove(request)?),
            Self::Policy(request) => request.prove(prover),
        }
    }

    async fn prove_async(&mut self, prover: &AsyncProverClient) -> Result<Proof, ClientError> {
        match self {
            Self::Base(request) => Ok(prover.prove(request).await?),
            Self::Policy(request) => request.prove_async(prover).await,
        }
    }

    fn with_compressed(self, compressed: CompressedDisclosure) -> Result<Self, TransferError> {
        match self {
            Self::Base(_) => Err(TransferError::CompressedWithoutWindow),
            Self::Policy(request) => request.with_compressed(compressed).map(Self::Policy),
        }
    }

    fn proven(self, proof: Proof) -> Result<TierBinding, TransferError> {
        Ok(match self {
            Self::Base(_) => TierBinding {
                proof: to_instruction_proof(proof)?,
                policy: None,
                approval_required: false,
            },
            Self::Policy(request) => {
                let PolicyBinding {
                    proof,
                    reads,
                    approval_required,
                } = request.proven(proof)?;
                TierBinding {
                    proof,
                    policy: Some(reads),
                    approval_required,
                }
            }
        })
    }
}

impl PolicyRequest {
    fn indexed_request(
        &self,
    ) -> Result<Option<zolana_client::prover::indexed::IndexedPolicyRequest>, ClientError> {
        let Some(mut data) = self.request.indexed.clone() else {
            return Ok(None);
        };
        if let PolicyProofKind::Compressed(compressed) = &self.kind {
            data.public_inputs.push(compressed.counters_disclosure_hash);
        }
        zolana_client::prover::indexed::IndexedPolicyRequest::new(
            self.body()?,
            self.proving_key()?,
            data,
        )
        .map(Some)
    }

    fn accept_indexed(
        &mut self,
        indexed: zolana_client::prover::indexed::IndexedProof,
    ) -> Result<Proof, ClientError> {
        use custom_ring_interface::{
            compressed_policy_verifying_key, delegate_policy_verifying_key, policy_verifying_key,
        };
        let key = match self.kind {
            PolicyProofKind::Ordinary => &policy_verifying_key::VERIFYINGKEY,
            PolicyProofKind::Compressed(_) => &compressed_policy_verifying_key::VERIFYINGKEY,
            PolicyProofKind::Delegate => &delegate_policy_verifying_key::VERIFYINGKEY,
        };
        // 2. Root contexts enter the transaction only after statement verification.
        zolana_client::prover::verify_proof_statement(
            &indexed.proof,
            indexed.resolution.public_input_hash,
            key,
        )?;
        self.reads.trees = indexed
            .resolution
            .trees
            .into_iter()
            .map(|tree| crate::PolicyTreeContext {
                tree: tree.tree,
                context: tree.context,
            })
            .collect();
        Ok(indexed.proof)
    }

    pub(crate) fn prove(&mut self, prover: &ProverClient) -> Result<Proof, ClientError> {
        match self.indexed_request()? {
            Some(request) => self.accept_indexed(prover.prove_indexed(&request)?),
            None => Ok(prover.prove(self)?),
        }
    }

    pub(crate) async fn prove_async(
        &mut self,
        prover: &AsyncProverClient,
    ) -> Result<Proof, ClientError> {
        match self.indexed_request()? {
            Some(request) => self.accept_indexed(prover.prove_indexed(&request).await?),
            None => Ok(prover.prove(self).await?),
        }
    }

    /// The compressed circuit folds the disclosure after the policy chain.
    fn with_compressed(mut self, compressed: CompressedDisclosure) -> Result<Self, TransferError> {
        if self.request.velocity.window_slots == 0 {
            return Err(TransferError::CompressedWithoutWindow);
        }
        use zolana_hasher::{Hasher, Poseidon};
        self.request.public_input_hash = Poseidon::hashv(&[
            &self.request.public_input_hash,
            &compressed.counters_disclosure_hash,
        ])
        .map_err(|_| TransferError::PolicyHashing)?;
        self.kind = PolicyProofKind::Compressed(compressed);
        Ok(self)
    }

    pub(crate) fn for_delegate(mut self) -> Self {
        self.kind = PolicyProofKind::Delegate;
        self
    }

    pub(crate) fn proven(self, proof: Proof) -> Result<PolicyBinding, TransferError> {
        Ok(PolicyBinding {
            proof: to_instruction_proof(proof)?,
            reads: self.reads,
            approval_required: self.approval_required,
        })
    }
}

pub(crate) struct PolicyBinding {
    pub proof: CustomRingProof,
    pub reads: PolicyReads,
    pub approval_required: bool,
}

struct TierBinding {
    proof: CustomRingProof,
    policy: Option<PolicyReads>,
    approval_required: bool,
}

/// Both witnesses built and the auditor encryption closed over the transfer's
/// `private_tx_hash`. Only the two proofs are outstanding.
struct WitnessedTransfer {
    request: TierRequest,
    #[cfg(feature = "solana-rpc")]
    window: Option<ProvedWindow>,
    tx_viewing_key: ViewingKey,
    proof_inputs: SppProofInputs,
    spp: SppWitness,
    payer: Address,
    trees: SpendTrees,
    interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    ring: CustomRing,
    cosigner: Option<Address>,
}

struct TransferAuthority<'a> {
    owner: Option<&'a NullifierKey>,
    /// Slot of the namespace-owned spend record a windowed velocity transfer
    /// carries, `RECORD_INPUT_SLOT`.
    spend_record: Option<usize>,
}

impl ProofAuthority for TransferAuthority<'_> {
    fn complete_inputs(
        &self,
        inputs: &mut [zolana_client::TransferInput],
    ) -> Result<(), ClientError> {
        if let Some(position) = self.spend_record {
            // 1. Only the namespace record uses the zero authority.
            let record = inputs.get_mut(position).ok_or(ClientError::NoInputs)?;
            zero_nullifier_key().complete_inputs(std::slice::from_mut(record))?;
        }
        if let Some(owner) = self.owner {
            owner.complete_inputs(inputs)?;
        }
        Ok(())
    }
}

pub(crate) enum SppWitness {
    Authority(Box<zolana_client::RingAuthorityProofResult>),
    Complete(Box<RingTransferProofResult>),
    Indexed(Box<PreparedIndexedTransfer>),
}

impl SppWitness {
    pub(crate) fn private_tx_hash(&self) -> [u8; 32] {
        match self {
            Self::Complete(result) => result.private_tx_hash,
            Self::Authority(result) => result.private_tx_hash,
            Self::Indexed(prepared) => prepared.private_tx_hash(),
        }
    }

    fn complete(
        &self,
        proof: Proof,
        transaction: &SppProofInputs,
    ) -> Result<TransactIxData, ClientError> {
        let shape = transaction.check_shape()?;
        let width = (
            shape.n_inputs() as u8,
            shape.n_outputs() as u8,
            N_PUBLIC_SLOTS as u8,
        );
        let (nullifiers, input_tree_indexes, tree_contexts, circuit) = match self {
            Self::Complete(result) => (
                &result.nullifiers,
                &result.input_tree_indexes,
                &result.tree_contexts,
                CircuitId::RingEddsa(width.0, width.1, width.2),
            ),
            Self::Authority(result) => (
                &result.nullifiers,
                &result.input_tree_indexes,
                &result.tree_contexts,
                CircuitId::RingAuthority(width.0, width.1, width.2),
            ),
            Self::Indexed(_) => {
                return Err(ClientError::Prover("unexpected complete proof".into()))
            }
        };
        RingInstructionData {
            external_data: &transaction.external_data,
            nullifiers,
            input_tree_indexes,
            tree_contexts,
            private_tx_hash: self.private_tx_hash(),
            proof: ProofCompressed::try_from(proof)?.to_transact_proof(),
            circuit,
        }
        .assemble()
        .map_err(|error| ClientError::Prover(error.to_string()))
    }

    pub(crate) fn prove(
        &self,
        prover: &ProverClient,
        transaction: &SppProofInputs,
    ) -> Result<TransactIxData, ClientError> {
        match self {
            Self::Authority(result) => {
                self.complete(prover.prove_ring_authority(&result.inputs)?, transaction)
            }
            Self::Complete(result) => {
                self.complete(prover.prove_transfer_ring(&result.inputs)?, transaction)
            }
            Self::Indexed(prepared) => Ok(prover.prove_indexed(prepared.as_ref())?.data),
        }
    }

    pub(crate) async fn prove_async(
        &self,
        prover: &AsyncProverClient,
        transaction: &SppProofInputs,
    ) -> Result<TransactIxData, ClientError> {
        match self {
            Self::Authority(result) => self.complete(
                prover.prove_ring_authority(&result.inputs).await?,
                transaction,
            ),
            Self::Complete(result) => self.complete(
                prover.prove_transfer_ring(&result.inputs).await?,
                transaction,
            ),
            Self::Indexed(prepared) => Ok(prover.prove_indexed(prepared.as_ref()).await?.data),
        }
    }
}

impl WitnessedTransfer {
    fn finish(
        self,
        spp_proof: TransactIxData,
        ring_proof: Proof,
    ) -> Result<ProvenTransfer, TransferError> {
        let TierBinding {
            proof,
            policy,
            approval_required,
        } = self.request.proven(ring_proof)?;
        Ok(ProvenTransfer {
            #[cfg(feature = "solana-rpc")]
            window: self.window,
            tx_viewing_key: self.tx_viewing_key,
            data: spp_proof,
            proof,
            owner_signers: self.proof_inputs.owner_signer_pubkeys()?,
            interface_transfer_accounts: self.interface_transfer_accounts,
            policy,
            cosigner: self.cosigner,
            approval_required,
            payer: self.payer,
            trees: self.trees,
            ring: self.ring,
        })
    }
}

impl ProvenTransfer {
    pub fn instruction(&self) -> Result<Instruction, TransferError> {
        CustomRingTransact {
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
        .instruction()
        .map_err(Into::into)
    }
}

impl RingDeposit<'_> {
    /// Fixes the note, every proving attempt deposits the same one.
    pub fn prepare<R: Rpc>(&self, rpc: &R) -> Result<PreparedRingDeposit, DepositError> {
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
            ring_data_hash: NO_RING_DATA_HASH,
            encrypted: RingDepositPlaintext {
                blinding,
                utxo_data: None,
                memo: None,
                ring_data: Vec::new(),
            }
            .encrypt(&self.recipient.viewing_pubkey())?,
        };
        // 1. The deposit setting or key escrow selects disclosure proving
        // before any deposit is sent.
        let key_registry = KeyRegistry::of(self.ring, &config);
        let disclosure = if key_registry.is_some() || self.ring.read_deposit_audit(rpc)? {
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
            let spp_instruction = zolana_program::instruction::RingDeposit {
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
            let address = self.recipient.shielded_address()?;
            let uncompressed = config.auditor_pubkey.to_p256()?.to_encoded_point(false);
            let mut auditor_uncompressed = [0; 65];
            auditor_uncompressed.copy_from_slice(uncompressed.as_bytes());
            let mut blindings = Zeroizing::new([[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS]);
            blindings[0] = blinding;
            Some(DepositDisclosure {
                context_hash,
                owner_utxo_hash: deposit.owner_utxo_hash,
                key: OutputKey {
                    owner_pk_hash: address.signing_pubkey.owner_proof_input_hash()?,
                    nullifier_pk: address.nullifier_pubkey,
                },
                blindings,
                encryption,
                auditor: config.auditor_pubkey,
                auditor_uncompressed,
                key_registry,
            })
        } else {
            None
        };
        Ok(PreparedRingDeposit {
            ring: self.ring,
            tree: self.tree,
            depositor: self.payer.pubkey(),
            cosigner: self.cosigner.map(Signer::pubkey),
            deposit,
            utxo: Utxo {
                owner: self.recipient.signing_pubkey(),
                asset: mint,
                amount: self.amount,
                blinding,
                ring_program_id: Some(self.ring.program_id()),
                data: Data::default(),
            },
            disclosure,
        })
    }

    /// A stale key-registry root re-proves the prepared note under a fresh root.
    #[cfg(feature = "solana-rpc")]
    pub fn send<I: Rpc>(
        self,
        env: DepositProofEnvironment<'_, I, zolana_client::SolanaRpc>,
    ) -> Result<RingDepositReceipt, DepositError> {
        let prepared = self.prepare(env.rpc)?;
        let utxo = prepared.utxo.clone();
        let signers: Vec<&dyn Signer> = self.cosigner.into_iter().collect();
        let status = crate::RingSubmission::new(prepared).send_until_settled(
            crate::SubmissionEnvironment {
                indexer: env.indexer,
                rpc: env.rpc,
                prover: env.prover,
                payer: self.payer,
                signers: &signers,
            },
        )?;
        match status {
            crate::SettledSubmission::Confirmed { signature, .. } => {
                Ok(RingDepositReceipt { signature, utxo })
            }
            crate::SettledSubmission::Failed { signature, error } => {
                Err(DepositError::Rejected { signature, error })
            }
        }
    }
}

/// A deposit whose note and auditor ciphertext are fixed, the proof is not.
pub struct PreparedRingDeposit {
    ring: CustomRing,
    tree: Address,
    depositor: Address,
    cosigner: Option<Address>,
    deposit: RingAssetDeposit,
    utxo: Utxo,
    /// `None` for an undisclosed deposit.
    disclosure: Option<DepositDisclosure>,
}

struct DepositDisclosure {
    context_hash: [u8; 32],
    owner_utxo_hash: [u8; 32],
    key: OutputKey,
    blindings: Zeroizing<[[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS]>,
    encryption: DepositEncryption,
    auditor: P256Pubkey,
    auditor_uncompressed: [u8; 65],
    key_registry: Option<KeyRegistry>,
}

impl PreparedRingDeposit {
    pub fn utxo(&self) -> &Utxo {
        &self.utxo
    }

    pub fn budget(&self) -> ComputeBudgetConfig {
        match self.disclosure {
            Some(_) => ComputeBudgetConfig::new(crate::AUDITED_DEPOSIT_COMPUTE_UNIT_LIMIT),
            None => ComputeBudgetConfig::for_instruction_count(1),
        }
    }

    pub fn prove<I: Rpc, R: Rpc>(
        &self,
        env: DepositProofEnvironment<'_, I, R>,
    ) -> Result<Instruction, DepositError> {
        crate::projection::retry_projection_lag(|| self.prove_once(&env))
    }

    fn prove_once<I: Rpc, R: Rpc>(
        &self,
        env: &DepositProofEnvironment<'_, I, R>,
    ) -> Result<Instruction, DepositError> {
        let Some(disclosure) = &self.disclosure else {
            return self.instruction(None, None);
        };
        // An escrowed ring proves the recipient's key is enrolled.
        let escrow = disclosure
            .key_registry
            .map(|registry| {
                if env.prover.proof_data_source() == ProofDataSource::Prover {
                    return registry.pending(env.rpc);
                }
                registry.openings(
                    ReadEnvironment {
                        indexer: env.indexer,
                        rpc: env.rpc,
                    },
                    &[Some(disclosure.key)],
                )
            })
            .transpose()?;
        let statement = disclosure.statement(escrow.as_ref())?;
        let proof = match disclosure.indexed_request(
            &statement,
            escrow.as_ref(),
            env.prover.proof_data_source(),
        )? {
            Some(request) => {
                disclosure.verify_deposit(env.prover.prove_indexed(&request)?, &statement)?
            }
            None => env.prover.prove(&disclosure.request(&statement))?,
        };
        self.instruction(Some(to_instruction_proof(proof)?), escrow)
    }

    pub async fn prove_async<I: AsyncRpc, R: AsyncRpc>(
        &self,
        env: AsyncTransferProofEnvironment<'_, I, R>,
    ) -> Result<Instruction, DepositError> {
        crate::projection::retry_projection_lag_async(|| self.prove_once_async(&env)).await
    }

    async fn prove_once_async<I: AsyncRpc, R: AsyncRpc>(
        &self,
        env: &AsyncTransferProofEnvironment<'_, I, R>,
    ) -> Result<Instruction, DepositError> {
        let Some(disclosure) = &self.disclosure else {
            return self.instruction(None, None);
        };
        let escrow = match disclosure.key_registry {
            Some(registry) if env.prover.proof_data_source() == ProofDataSource::Prover => {
                Some(registry.pending_async(env.rpc).await?)
            }
            Some(registry) => Some(
                registry
                    .openings_async(
                        ReadEnvironment {
                            indexer: env.indexer,
                            rpc: env.rpc,
                        },
                        &[Some(disclosure.key)],
                    )
                    .await?,
            ),
            None => None,
        };
        let statement = disclosure.statement(escrow.as_ref())?;
        let proof = match disclosure.indexed_request(
            &statement,
            escrow.as_ref(),
            env.prover.proof_data_source(),
        )? {
            Some(request) => {
                disclosure.verify_deposit(env.prover.prove_indexed(&request).await?, &statement)?
            }
            None => env.prover.prove(&disclosure.request(&statement)).await?,
        };
        self.instruction(Some(to_instruction_proof(proof)?), escrow)
    }

    fn instruction(
        &self,
        proof: Option<CustomRingProof>,
        escrow: Option<EscrowedKeys>,
    ) -> Result<Instruction, DepositError> {
        Ok(Deposit {
            ring: self.ring,
            tree: self.tree,
            depositor: self.depositor,
            deposits: vec![self.deposit.clone()],
            proof,
            escrow: EscrowBinding::of(escrow.map(|escrow| escrow.root)),
            cosigner: self.cosigner,
        }
        .instruction()?)
    }
}

struct DepositStatement {
    public_input_hash: [u8; 32],
    owner_pk_hashes: [[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    nullifier_pks: [[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    keys: [Option<RegistryKeyOpening>; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    key_registry_root: Option<[u8; 32]>,
}

impl DepositDisclosure {
    fn indexed_request(
        &self,
        statement: &DepositStatement,
        escrow: Option<&EscrowedKeys>,
        source: ProofDataSource,
    ) -> Result<Option<zolana_client::prover::indexed::IndexedDepositRequest>, ClientError> {
        if source == ProofDataSource::Client {
            return Ok(None);
        }
        let (Some(escrow), Some(registry)) = (escrow, self.key_registry) else {
            return Ok(None);
        };
        zolana_client::prover::indexed::IndexedDepositRequest::new(
            &self.request(statement),
            zolana_client::prover::indexed::IndexedRegistry {
                ring_program_id: registry.ring.program_id(),
                root: escrow.root.root,
                next_index: escrow.root.next_index,
            },
        )
        .map(Some)
    }

    fn verify_deposit(
        &self,
        proof: Proof,
        statement: &DepositStatement,
    ) -> Result<Proof, ClientError> {
        zolana_client::prover::verify_proof_statement(
            &proof,
            statement.public_input_hash,
            &custom_ring_interface::deposit_verifying_key::VERIFYINGKEY,
        )?;
        Ok(proof)
    }

    fn statement(&self, escrow: Option<&EscrowedKeys>) -> Result<DepositStatement, DepositError> {
        let key_registry_root = escrow.map(|escrow| escrow.root.root);
        let public_input_hash = custom_ring_interface::DepositPublicInput {
            context_hash: &self.context_hash,
            owner_utxo_hashes: &[self.owner_utxo_hash],
            ciphertexts: &self.encryption.ciphertexts,
            auditor_pk: self.auditor.as_bytes(),
            eph_pk: self.encryption.ephemeral_pk.as_bytes(),
            key_registry_root: key_registry_root.as_ref(),
        }
        .hash()
        .map_err(|_| DepositError::Hashing)?;
        let mut keys = [None; MAX_RING_DEPOSIT_AUDIT_SLOTS];
        if let Some(escrow) = escrow {
            keys[..escrow.keys.len()].copy_from_slice(&escrow.keys);
        }
        let mut owner_pk_hashes = [[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
        owner_pk_hashes[0] = self.key.owner_pk_hash;
        let mut nullifier_pks = [[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
        nullifier_pks[0] = self.key.nullifier_pk;
        Ok(DepositStatement {
            public_input_hash,
            owner_pk_hashes,
            nullifier_pks,
            keys,
            key_registry_root,
        })
    }

    fn request<'a>(
        &'a self,
        statement: &'a DepositStatement,
    ) -> crate::instructions::deposit_request::RingDepositProofRequest<'a> {
        crate::instructions::deposit_request::RingDepositProofRequest {
            public_input_hash: &statement.public_input_hash,
            context_hash: &self.context_hash,
            count: 1,
            owner_pk_hashes: &statement.owner_pk_hashes,
            nullifier_pks: &statement.nullifier_pks,
            blindings: &self.blindings,
            keys: &statement.keys,
            key_registry_root: statement.key_registry_root.as_ref(),
            ephemeral_sk: &self.encryption.ephemeral_sk,
            auditor_pk: &self.auditor_uncompressed,
        }
    }
}

/// The raw id of a pool tree, every UTXO in it hashes under this id.
pub fn tree_id<R: Rpc>(rpc: &R, tree: Address) -> Result<u16, TransferError> {
    Ok(read_tree_state(rpc, tree)?.tree.id)
}

pub async fn tree_id_async<R: AsyncRpc>(rpc: &R, tree: Address) -> Result<u16, TransferError> {
    Ok(read_tree_state_async(rpc, tree).await?.tree.id)
}

pub(crate) struct TreeState {
    /// Nullifier slots left above the state tree's full capacity, queued ones counted.
    pub dummy_input_headroom: u64,
    pub tree: PoolTree,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SpendTrees {
    /// One per input group, in the order the inputs name them.
    pub inputs: Vec<Address>,
    pub output: Address,
    /// SPP admits dummy inputs only when every input tree has headroom for its group.
    pub allow_dummy_inputs: bool,
}

struct InputGroup {
    tree: PoolTree,
    positions: Vec<usize>,
}

/// Inputs by the tree they name, trees in first-use order.
fn input_groups(inputs: &[SppProofInputUtxo]) -> Vec<InputGroup> {
    let mut groups: Vec<InputGroup> = Vec::new();
    for (position, input) in inputs.iter().enumerate() {
        match groups
            .iter_mut()
            .find(|group| group.tree.id == input.tree_id)
        {
            Some(group) => group.positions.push(position),
            None => groups.push(InputGroup {
                tree: PoolTree::from_id(input.tree_id),
                positions: vec![position],
            }),
        }
    }
    groups
}

pub(crate) struct SpendTreePlan {
    groups: Vec<InputGroup>,
    output: PoolTree,
}

impl SpendTreePlan {
    pub fn new(inputs: &[SppProofInputUtxo], output: PoolTree) -> Self {
        Self {
            groups: input_groups(inputs),
            output,
        }
    }

    pub fn read<R: Rpc>(self, rpc: &R) -> Result<SpendTrees, TransferError> {
        let inputs = self
            .groups
            .iter()
            .map(|group| read_tree_state(rpc, group.tree.address))
            .collect::<Result<Vec<_>, _>>()?;
        let output = read_tree_state(rpc, self.output.address)?;
        self.bind(inputs, output)
    }

    pub async fn read_async<R: AsyncRpc>(self, rpc: &R) -> Result<SpendTrees, TransferError> {
        let inputs = futures::future::try_join_all(
            self.groups
                .iter()
                .map(|group| read_tree_state_async(rpc, group.tree.address)),
        )
        .await?;
        let output = read_tree_state_async(rpc, self.output.address).await?;
        self.bind(inputs, output)
    }

    /// Every UTXO hash commits to its tree id, a tree under another id proves nothing.
    fn bind(self, inputs: Vec<TreeState>, output: TreeState) -> Result<SpendTrees, TransferError> {
        for (expected, state) in self
            .groups
            .iter()
            .map(|group| &group.tree)
            .chain([&self.output])
            .zip(inputs.iter().chain([&output]))
        {
            if state.tree.id != expected.id {
                return Err(TransferError::TreeIdMismatch {
                    tree: expected.address,
                    expected: state.tree.id,
                    found: expected.id,
                });
            }
        }
        Ok(SpendTrees {
            allow_dummy_inputs: self
                .groups
                .iter()
                .zip(&inputs)
                .all(|(group, state)| state.dummy_input_headroom >= group.positions.len() as u64),
            inputs: self.groups.iter().map(|group| group.tree.address).collect(),
            output: self.output.address,
        })
    }
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
        tree: PoolTree {
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

pub(crate) struct SpendSet {
    pub inputs: Option<Vec<TransferInputUtxo>>,
    pub trees: SpendTrees,
}

struct SpendGroup {
    tree: Address,
    positions: Vec<usize>,
    /// Hashes of the group's real spends, whose inclusion is proved.
    utxo_hashes: Vec<[u8; 32]>,
    /// Nullifiers of every spend in the group, real and dummy, whose absence is proved.
    nullifiers: Vec<[u8; 32]>,
}

struct GroupProofs {
    states: Vec<MerkleProof>,
    non_inclusions: Vec<NonInclusionProof>,
}

#[must_use = "use the updated transfer"]
pub(crate) struct RingSpendInputs<'a, I> {
    pub indexer: &'a I,
    pub input_utxos: &'a [SppProofInputUtxo],
}

impl<I> RingSpendInputs<'_, I> {
    fn groups(&self) -> Vec<SpendGroup> {
        input_groups(self.input_utxos)
            .into_iter()
            .map(|group| {
                let inputs = group
                    .positions
                    .iter()
                    .map(|&position| &self.input_utxos[position]);
                SpendGroup {
                    tree: group.tree.address,
                    utxo_hashes: inputs
                        .clone()
                        .filter(|input_utxo| !input_utxo.is_dummy())
                        .map(SppProofInputUtxo::hash)
                        .collect(),
                    nullifiers: inputs.map(SppProofInputUtxo::nullifier).collect(),
                    positions: group.positions,
                }
            })
            .collect()
    }
}

impl<I: AsyncRpc> RingSpendInputs<'_, I> {
    pub async fn load_async(self) -> Result<Vec<TransferInputUtxo>, TransferError> {
        let groups = self.groups();
        let proofs = futures::future::try_join_all(groups.iter().map(|group| async {
            let (states, non_inclusions) = futures::try_join!(
                self.indexer
                    .get_merkle_proofs(group.tree, group.utxo_hashes.clone(), None),
                self.indexer
                    .get_non_inclusion_proofs(group.tree, group.nullifiers.clone(), None),
            )?;
            Ok::<_, ClientError>(GroupProofs {
                states: states.proofs,
                non_inclusions: non_inclusions.proofs,
            })
        }))
        .await?;
        self.assemble(&groups, proofs)
    }
}

impl<I: Rpc> RingSpendInputs<'_, I> {
    pub fn load(self) -> Result<Vec<TransferInputUtxo>, TransferError> {
        let groups = self.groups();
        let proofs = groups
            .iter()
            .map(|group| {
                Ok(GroupProofs {
                    states: self
                        .indexer
                        .get_merkle_proofs(group.tree, group.utxo_hashes.clone(), None)?
                        .proofs,
                    non_inclusions: self
                        .indexer
                        .get_non_inclusion_proofs(group.tree, group.nullifiers.clone(), None)?
                        .proofs,
                })
            })
            .collect::<Result<Vec<_>, ClientError>>()?;
        self.assemble(&groups, proofs)
    }
}

impl<I> RingSpendInputs<'_, I> {
    /// Pairs each spend with its tree's proofs, in the caller's input order.
    fn assemble(
        self,
        groups: &[SpendGroup],
        proofs: Vec<GroupProofs>,
    ) -> Result<Vec<TransferInputUtxo>, TransferError> {
        if proofs.len() != groups.len() {
            return Err(TransferError::IncompleteProofSet);
        }
        let mut placed = Vec::with_capacity(self.input_utxos.len());
        for (
            group,
            GroupProofs {
                states,
                non_inclusions,
            },
        ) in groups.iter().zip(proofs)
        {
            if states.len() != group.utxo_hashes.len()
                || non_inclusions.len() != group.positions.len()
            {
                return Err(TransferError::IncompleteProofSet);
            }
            let mut states = states.into_iter();
            for (&position, nullifier) in group.positions.iter().zip(non_inclusions) {
                let input_utxo = &self.input_utxos[position];
                let (proof, nullifier_proof) = if input_utxo.is_dummy() {
                    (None, Some(nullifier))
                } else {
                    let state = states.next().ok_or(TransferError::IncompleteProofSet)?;
                    (Some(SpendProof { state, nullifier }), None)
                };
                placed.push((
                    position,
                    TransferInputUtxo {
                        utxo: input_utxo.clone(),
                        proof,
                        nullifier_proof,
                    },
                ));
            }
        }
        placed.sort_unstable_by_key(|(position, _)| *position);
        Ok(placed.into_iter().map(|(_, input)| input).collect())
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
    use zolana_interface::event::MessageData;
    use zolana_interface::instruction::instruction_data::transact::ring_confidential_encrypted_output_body;
    use zolana_program::instruction::TransactSolTransferAccounts;
    use zolana_transaction::keys::LocalShieldedKeys;
    use zolana_transaction::serialization::{confidential::Confidential, DecodeCx};
    use zolana_transaction::{Mint, UtxoSerialization};

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
        let spends = RingSpendInputs {
            indexer: &(),
            input_utxos: &input_utxos,
        };
        let groups = spends.groups();
        let inputs = spends
            .assemble(
                &groups,
                vec![GroupProofs {
                    states: vec![merkle],
                    non_inclusions: vec![non_inclusion],
                }],
            )
            .expect("one real input_utxo pairs with its proofs");
        let input = inputs.first().expect("one assembled input_utxo");
        assert_eq!(input.utxo.data_hash, Some([7u8; 32]));
        assert_eq!(input.utxo.ring_data_hash, Some([8u8; 32]));
    }

    fn spend(tree_id: u16, amount: u64) -> SppProofInputUtxo {
        let owner = ShieldedKeypair::new_ed25519().expect("owner");
        zolana_test_utils::utxo::wallet(
            Utxo {
                owner: owner.signing_pubkey(),
                asset: Mint::SOL,
                amount,
                blinding: random_blinding(),
                ring_program_id: Some(ring().program_id()),
                data: Data::default(),
            },
            &owner.nullifier_key,
            tree_id,
            amount,
            None,
            None,
        )
        .expect("input")
        .into()
    }

    fn state_proof(leaf: [u8; 32]) -> MerkleProof {
        MerkleProof {
            leaf,
            merkle_context: MerkleContext {
                tree_type: 0,
                tree: Address::default(),
            },
            path: vec![[0u8; 32]; 32],
            leaf_index: 0,
            root: [3u8; 32],
            root_seq: 1,
            root_index: 0,
        }
    }

    fn absence_proof(leaf: [u8; 32]) -> NonInclusionProof {
        NonInclusionProof {
            leaf,
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
        }
    }

    /// Each tree answers for its own group, the proofs return in input order.
    #[test]
    fn spends_in_two_trees_fetch_per_tree_and_keep_their_order() {
        let mut inputs = [spend(4, 1), spend(4, 2), spend(9, 3), spend(9, 4)];
        inputs[3] = SppProofInputUtxo::dummy(9).expect("dummy");
        let spends = RingSpendInputs {
            indexer: &(),
            input_utxos: &inputs,
        };
        let groups = spends.groups();
        assert_eq!(
            groups.iter().map(|group| group.tree).collect::<Vec<_>>(),
            vec![
                zolana_interface::pda::tree(4),
                zolana_interface::pda::tree(9)
            ]
        );
        assert_eq!(groups[1].positions, vec![2, 3]);
        assert_eq!(groups[1].utxo_hashes, vec![inputs[2].hash()]);
        assert_eq!(groups[1].nullifiers.len(), 2);
        let proofs = groups
            .iter()
            .map(|group| GroupProofs {
                states: group.utxo_hashes.iter().copied().map(state_proof).collect(),
                non_inclusions: group
                    .nullifiers
                    .iter()
                    .copied()
                    .map(absence_proof)
                    .collect(),
            })
            .collect();
        let assembled = spends.assemble(&groups, proofs).expect("assembled");
        for (input, assembled) in inputs.iter().zip(&assembled) {
            let nullifier = match (&assembled.proof, &assembled.nullifier_proof) {
                (Some(proof), None) => proof.nullifier.leaf,
                (None, Some(proof)) => proof.leaf,
                _ => panic!("a spend carries exactly one proof kind"),
            };
            assert_eq!(nullifier, input.nullifier());
        }
    }

    #[test]
    fn spend_trees_allow_dummies_only_when_every_group_has_headroom() {
        let inputs = [spend(4, 1), spend(9, 2), spend(9, 3)];
        let state = |id: u16, headroom: u64| TreeState {
            dummy_input_headroom: headroom,
            tree: PoolTree::from_id(id),
        };
        let plan = || SpendTreePlan::new(&inputs, PoolTree::from_id(4));
        let trees = plan()
            .bind(vec![state(4, 1), state(9, 2)], state(4, 0))
            .expect("bound");
        assert_eq!(
            trees.inputs,
            vec![PoolTree::from_id(4).address, PoolTree::from_id(9).address]
        );
        assert!(trees.allow_dummy_inputs);
        assert!(
            !plan()
                .bind(vec![state(4, 1), state(9, 1)], state(4, 0))
                .expect("bound")
                .allow_dummy_inputs
        );
        assert!(matches!(
            plan().bind(vec![state(4, 1), state(8, 2)], state(4, 0)),
            Err(TransferError::TreeIdMismatch { found: 9, .. })
        ));
    }

    /// Input tree ids once the record sits at slot one and dummies fill
    /// `n_inputs` slots.
    fn record_input_trees(
        spend_trees: &[u16],
        record_tree: u16,
        n_inputs: usize,
    ) -> Result<Vec<u16>, TransferError> {
        let sender = ShieldedKeypair::new_ed25519().expect("sender");
        let inputs = spend_trees
            .iter()
            .enumerate()
            .map(|(leaf_index, &tree_id)| {
                zolana_test_utils::utxo::wallet(
                    Utxo {
                        owner: sender.signing_pubkey(),
                        asset: Mint::SOL,
                        amount: 1,
                        blinding: random_blinding(),
                        ring_program_id: None,
                        data: Data::default(),
                    },
                    &sender.nullifier_key,
                    tree_id,
                    leaf_index as u64,
                    None,
                    None,
                )
                .expect("input")
            })
            .collect();
        let mut transaction =
            ConfidentialTransaction::new(inputs, solana_signer::Signer::pubkey(&sender))
                .expect("transaction");
        transaction
            .transfer_sol(&sender.shielded_address().expect("address"), 1)
            .expect("transfer");
        check_record_tree_count(&transaction, record_tree)?;
        let mut proof_inputs = transaction.encrypt(&sender).expect("encrypted");
        assert!(proof_inputs
            .input_utxos
            .first()
            .is_some_and(|input| !input.is_dummy()));
        place_record_input(
            &mut proof_inputs.input_utxos,
            spend(record_tree, 0),
            n_inputs,
        )?;
        Ok(proof_inputs
            .input_utxos
            .iter()
            .map(|input| input.tree_id)
            .collect())
    }

    #[test]
    fn the_record_takes_slot_one_and_the_remaining_money_follows() {
        assert_eq!(
            record_input_trees(&[4, 9], 4, 4).expect("ordered"),
            vec![4, 4, 9, 4]
        );
    }

    #[test]
    fn dummies_after_the_record_take_the_first_money_tree() {
        assert_eq!(
            record_input_trees(&[4], 9, 4).expect("ordered"),
            vec![4, 9, 4, 4]
        );
    }

    /// One money input and two money inputs in the same tree produce the same
    /// public tree pattern, so the pattern reveals neither the record nor the
    /// real input count.
    #[test]
    fn the_input_tree_pattern_does_not_change_with_the_real_input_count() {
        let one = record_input_trees(&[4], 9, 4).expect("one money input");
        let two = record_input_trees(&[4, 4], 9, 4).expect("two money inputs");
        assert_eq!(one, vec![4, 9, 4, 4]);
        assert_eq!(one, two);
    }

    #[test]
    fn a_record_without_a_free_input_slot_is_refused() {
        assert!(matches!(
            record_input_trees(&[4, 9], 4, 2),
            Err(TransferError::PolicyShapeUnsupported)
        ));
    }

    #[test]
    fn a_record_tree_past_the_input_tree_limit_is_refused() {
        let full: Vec<u16> = (1..=MAX_INPUT_TREES as u16).collect();
        assert!(record_input_trees(&full, 1, MAX_INPUT_TREES + 2).is_ok());
        assert!(matches!(
            record_input_trees(&full, 99, MAX_INPUT_TREES + 2),
            Err(TransferError::Transaction(TransactionError::TooManyInputTrees { got, max }))
                if got == MAX_INPUT_TREES + 1 && max == MAX_INPUT_TREES
        ));
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
            derived.first().unwrap().pubkey(),
            keypair
                .get_transaction_viewing_key(&first_nullifier)
                .unwrap()
                .pubkey()
        );
    }

    /// A self-paid ring transfer of `sent` out of 5 lamports, padded to
    /// `IN2_OUT2`, before its record moves in.
    struct RecordSlotsFixture {
        sender: ShieldedKeypair,
        recipient: ShieldedKeypair,
        sender_tag: ResolvedOwnerTag,
        tx_viewing_key: ViewingKey,
        proof_inputs: SppProofInputs,
    }

    impl RecordSlotsFixture {
        fn new(sent: u64) -> Self {
            let sender = ShieldedKeypair::new_ed25519().unwrap();
            let recipient = ShieldedKeypair::new_ed25519().unwrap();
            let input = zolana_test_utils::utxo::wallet(
                Utxo {
                    owner: sender.signing_pubkey(),
                    asset: Mint::SOL,
                    amount: 5,
                    blinding: random_blinding(),
                    ring_program_id: Some(ring().program_id()),
                    data: Data::default(),
                },
                &sender.nullifier_key,
                4,
                0,
                None,
                None,
            )
            .unwrap();
            let mut tx = ConfidentialTransaction::new_with_ring(
                vec![input],
                solana_signer::Signer::pubkey(&sender),
                ring().program_id(),
            )
            .unwrap();
            tx.transfer_sol(&recipient.shielded_address().unwrap(), sent)
                .unwrap();
            tx.pad_utxos(
                zolana_interface::shape::Shape::IN2_OUT2,
                &sender.shielded_address().unwrap(),
            )
            .unwrap();
            let sender_tag = tx.sender_owner_tag(&sender.signing_pubkey()).unwrap();
            let tx_viewing_key = sender
                .get_transaction_viewing_key(tx.first_nullifier())
                .unwrap();
            let proof_inputs = tx.encrypt(&sender).unwrap();
            Self {
                sender,
                recipient,
                sender_tag,
                tx_viewing_key,
                proof_inputs,
            }
        }

        fn plan(&self, record_blinding: [u8; 32]) -> VelocityPlan {
            let record_owner = ShieldedAddress::for_pda(
                &ring().namespace_pda(),
                zero_nullifier_key().pubkey().unwrap(),
                self.tx_viewing_key.pubkey(),
            );
            VelocityPlan {
                input: spend(9, 0),
                output: SppProofOutputUtxo {
                    blinding: record_blinding,
                    ..SppProofOutputUtxo::new(Mint::SOL, 0, record_owner).unwrap()
                },
                record_message: MessageData {
                    view_tag: [0; 32],
                    data: Vec::new(),
                },
                counters_message: MessageData {
                    view_tag: [0; 32],
                    data: Vec::new(),
                },
                proof_input: VelocityProofInput::off(RingIdentity {
                    ring_id: [1; 32],
                    namespace_owner_hash: [2; 32],
                }),
                shape: zolana_interface::shape::Shape::IN4_OUT4,
            }
        }

        fn insert(&mut self, plan: &VelocityPlan) -> Result<(), TransferError> {
            RecordSlots {
                plan,
                tx_viewing_key: &self.tx_viewing_key,
                sender_tag: self.sender_tag,
            }
            .insert(&mut self.proof_inputs)
        }

        fn viewing_key(&self, owner: &ShieldedAddress) -> &ViewingKey {
            [&self.sender, &self.recipient]
                .into_iter()
                .find(|keypair| keypair.viewing_pubkey() == owner.viewing_pubkey)
                .map(|keypair| &keypair.viewing_key)
                .unwrap()
        }
    }

    /// With change the money fills `IN2_OUT2`, so the record needs a fresh
    /// dummy; without change the dummy `pad_utxos` placed is copied.
    #[test]
    fn the_record_output_takes_slot_zero_and_the_money_outputs_are_resealed_at_their_shifted_slots()
    {
        for sent in [1, 5] {
            let mut fixture = RecordSlotsFixture::new(sent);
            let before = fixture.proof_inputs.clone();
            let money: Vec<_> = before
                .output_utxos
                .iter()
                .zip(&before.external_data.outputs)
                .zip(&before.external_data.resolved_owner_tags)
                .filter(|((output, _), _)| !output.is_dummy())
                .collect();
            assert_eq!(money.len(), if sent == 1 { 2 } else { 1 });
            let blindings = OutputBlindings::of(&before).unwrap();
            let plan = fixture.plan(blindings.at(RECORD_OUTPUT_SLOT as u32).unwrap());
            fixture.insert(&plan).unwrap();
            let after = &fixture.proof_inputs;
            let external = &after.external_data;
            assert_eq!(after.check_shape().unwrap(), plan.shape);
            assert_eq!(external.outputs.len(), plan.shape.n_outputs());
            assert_eq!(external.resolved_owner_tags.len(), plan.shape.n_outputs());

            let record_tag = plan
                .output
                .owner_address
                .unwrap()
                .signing_pubkey
                .confidential_view_tag()
                .unwrap();
            let record = external.outputs.get(RECORD_OUTPUT_SLOT).unwrap();
            assert_eq!(
                after.output_utxos.get(RECORD_OUTPUT_SLOT),
                Some(&plan.output)
            );
            assert_eq!(
                (record.utxo_hash, record.owner_tag),
                (
                    plan.output.hash(after.output_tree_id).unwrap(),
                    OwnerTag::Inline(record_tag)
                )
            );
            assert_eq!(
                external.resolved_owner_tags.get(RECORD_OUTPUT_SLOT),
                Some(&record_tag)
            );

            for (money_index, ((output, encoded), resolved)) in money.iter().enumerate() {
                let slot = RECORD_OUTPUT_SLOT + 1 + money_index;
                let slot_index = u32::try_from(slot).unwrap();
                let blinding = blindings.at(slot_index).unwrap();
                let moved = after.output_utxos.get(slot).unwrap();
                assert_eq!(
                    moved,
                    &SppProofOutputUtxo {
                        blinding,
                        ..(*output).clone()
                    }
                );
                let published = external.outputs.get(slot).unwrap();
                assert_eq!(
                    (published.utxo_hash, published.owner_tag),
                    (moved.hash(after.output_tree_id).unwrap(), encoded.owner_tag)
                );
                assert_eq!(external.resolved_owner_tags.get(slot), Some(*resolved));
                let owner = moved.owner_address.unwrap();
                let body = published
                    .data
                    .as_deref()
                    .and_then(ring_confidential_encrypted_output_body)
                    .unwrap();
                let plaintext = Confidential::decode(
                    body,
                    &DecodeCx {
                        viewing_key: fixture.viewing_key(&owner),
                        tx_viewing_pk: Some(fixture.tx_viewing_key.pubkey()),
                        salt: Some(external.salt),
                        slot_index,
                        first_nullifier: None,
                    },
                )
                .unwrap();
                assert_eq!(
                    (
                        plaintext.amount,
                        plaintext.blinding,
                        plaintext.ring_program_id
                    ),
                    (moved.amount, blinding, Some(ring().program_id()))
                );
            }

            let sender_tag = fixture.sender_tag;
            let recipient_tag = fixture
                .recipient
                .signing_pubkey()
                .confidential_view_tag()
                .unwrap();
            // A fresh dummy names the self-paid sender as its change does; a
            // copied one keeps the recipient tag `pad_utxos` published.
            let dummy_tag = if sent == 1 {
                assert_eq!(sender_tag.tag, OwnerTag::Account(0));
                sender_tag
            } else {
                ResolvedOwnerTag {
                    tag: OwnerTag::Inline(recipient_tag),
                    resolved: recipient_tag,
                }
            };
            let first_dummy = RECORD_OUTPUT_SLOT + 1 + money.len();
            assert!(first_dummy < plan.shape.n_outputs());
            for slot in first_dummy..plan.shape.n_outputs() {
                let dummy = after.output_utxos.get(slot).unwrap();
                assert_eq!(
                    dummy,
                    &SppProofOutputUtxo {
                        blinding: blindings.at(u32::try_from(slot).unwrap()).unwrap(),
                        ring_program_id: Some(ring().program_id()),
                        owner_tag: Some(dummy_tag.resolved),
                        ..Default::default()
                    }
                );
                let published = external.outputs.get(slot).unwrap();
                assert_eq!(
                    (published.utxo_hash, published.owner_tag),
                    (dummy.hash(after.output_tree_id).unwrap(), dummy_tag.tag)
                );
                assert_eq!(
                    external.resolved_owner_tags.get(slot),
                    Some(&dummy_tag.resolved)
                );
            }
        }
    }

    #[test]
    fn record_slots_place_the_record_input_at_slot_one_and_keep_money0_first() {
        for sent in [1, 5] {
            let mut fixture = RecordSlotsFixture::new(sent);
            let money_input = fixture.proof_inputs.input_utxos.first().cloned().unwrap();
            let blindings = OutputBlindings::of(&fixture.proof_inputs).unwrap();
            let plan = fixture.plan(blindings.at(RECORD_OUTPUT_SLOT as u32).unwrap());
            fixture.insert(&plan).unwrap();
            let inputs = &fixture.proof_inputs.input_utxos;
            assert_eq!(
                inputs
                    .iter()
                    .map(|input| (input.is_dummy(), input.tree_id))
                    .collect::<Vec<_>>(),
                vec![(false, 4), (false, 9), (true, 4), (true, 4)]
            );
            assert_eq!(
                inputs
                    .get(RECORD_INPUT_SLOT)
                    .map(SppProofInputUtxo::nullifier),
                Some(plan.input.nullifier())
            );
            assert_eq!(
                fixture.proof_inputs.first_nullifier().unwrap(),
                money_input.nullifier()
            );
        }
    }

    #[test]
    fn a_record_output_without_the_slot_zero_blinding_is_refused() {
        let mut fixture = RecordSlotsFixture::new(1);
        let blindings = OutputBlindings::of(&fixture.proof_inputs).unwrap();
        let plan = fixture.plan(blindings.at(1).unwrap());
        assert!(matches!(
            fixture.insert(&plan),
            Err(TransferError::Client(ClientError::OutputBlindingMismatch { index }))
                if index == RECORD_OUTPUT_SLOT
        ));
    }
}
