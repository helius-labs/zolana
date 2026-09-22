use custom_ring_interface::PolicyConfig;
use futures::future::try_join;
use rand::{rngs::OsRng, RngCore};
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
    Proof, ProofAuthority, ProofCompressed, ProverClient, RingTransferProofResult,
    RingTransferProver, Rpc, SettlementAccountValidation, SpendProof, TransferInputUtxo,
    TransferInputs,
};
use zolana_interface::event::OutputDataEncoding;
use zolana_interface::{
    instruction::{
        tag::RING_TRANSACT, CircuitId, DepositAsset, DepositBuildError, RingAssetDeposit,
        TransactInterfaceTransferAccounts, TransactIxData, TransactProof,
    },
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{
    random_blinding, KeypairError, NullifierKey, P256Pubkey, ShieldedKeypair, ViewingKey,
};
use zolana_ring_policy::RuleTable;
use zolana_transaction::{
    instructions::transact::{ConfidentialTransaction, SppProofInputs, SppProofOutputUtxo},
    keys::{ShieldedKeys, TransactionKeyRequest},
    owner_utxo_hash,
    utxo::SppProofInputUtxo,
    Data, EncryptedScheme, Mint, RingDepositPlaintext, TransactionError, Utxo, WalletUtxo,
};
use zolana_tree::{TreeAccount, TreeError};

use crate::{
    policy_config_table, to_instruction_proof,
    witness::{CustomRingWitness, CustomRingWitnessInput, TransactRoots},
    AccountReadError, CustomRing, CustomRingBaseProofRequest, CustomRingPolicyProofRequest,
    CustomRingProof, CustomRingProofError, CustomRingProofInputError, CustomRingProofParams,
    CustomRingTransact, Deposit, EncryptedAudit, PendingCustomRingProof, PolicyMatchError,
};

const NO_RING_DATA_HASH: [u8; 32] = [0u8; 32];

#[must_use = "prove or discard the transfer explicitly"]
pub struct CustomRingTransfer<'a> {
    ring: CustomRing,
    sender: &'a (dyn ShieldedKeys + Send + Sync),
    nullifier_key: Option<&'a NullifierKey>,
    transaction: ConfidentialTransaction,
    interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    input_tree: Option<Address>,
    output_tree: Option<Address>,
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
    payer: Address,
    input_tree: Address,
    output_tree: Address,
    /// The pinned entries tree for a policy ring, `None` for an audit-only ring.
    entries_tree: Option<Address>,
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
    #[error("transaction has padded change slots, build it with ConfidentialTransaction::with_compact_change")]
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
        }
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
        let staged = self.stage(config.auditor_pubkey)?;
        // The tree is read and validated first. A tree that is absent, owned by
        // another program, or not a tree account at all fails here rather than
        // after the indexer has served a full inclusion and non-inclusion proof
        // set that nothing can use.
        let input_tree = read_tree_state(environment.rpc, staged.input_tree)?;
        let output_tree = read_tree_state(environment.rpc, staged.output_tree)?;
        staged.check_tree_ids(input_tree.tree_id, output_tree.tree_id)?;
        let allow_dummy_inputs =
            input_tree.dummy_input_headroom >= staged.proof_inputs.input_utxos.len() as u64;
        let input_utxos = RingSpendInputs {
            indexer: environment.indexer,
            tree: staged.input_tree,
            input_utxos: &staged.proof_inputs.input_utxos,
        }
        .load()?;
        let tier = if config.has_policy {
            staged.policy_tier(&environment)?
        } else {
            Tier::Base
        };
        let (request, witnessed) = staged.witness(input_utxos, allow_dummy_inputs, tier)?;
        let spp_proof =
            ProofCompressed::try_from(environment.prover.prove_transfer_ring(witnessed.spp())?)?
                .to_transact_proof();
        let ring_proof = environment.prover.prove(&request)?;
        witnessed.finish(spp_proof, request.proven(ring_proof)?)
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
        let staged = self.stage(config.auditor_pubkey)?;
        // Same ordering reason as the blocking path: validate the tree before
        // asking the indexer for proofs against it.
        let input_tree = read_tree_state_async(environment.rpc, staged.input_tree).await?;
        let output_tree = read_tree_state_async(environment.rpc, staged.output_tree).await?;
        staged.check_tree_ids(input_tree.tree_id, output_tree.tree_id)?;
        let allow_dummy_inputs =
            input_tree.dummy_input_headroom >= staged.proof_inputs.input_utxos.len() as u64;
        let input_utxos = RingSpendInputs {
            indexer: environment.indexer,
            tree: staged.input_tree,
            input_utxos: &staged.proof_inputs.input_utxos,
        }
        .load_async()
        .await?;
        let tier = if config.has_policy {
            staged.policy_tier_async(&environment).await?
        } else {
            Tier::Base
        };
        let (request, witnessed) = staged.witness(input_utxos, allow_dummy_inputs, tier)?;
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
            environment.prover.prove(&request),
        )
        .await?;
        witnessed.finish(
            ProofCompressed::try_from(spp)?.to_transact_proof(),
            request.proven(ring)?,
        )
    }

    /// Everything before the first read: validation, the transaction viewing
    /// key, and the auditor encryption that has to be inside `external_data`
    /// before anything hashes it.
    fn stage(self, auditor_pk: P256Pubkey) -> Result<StagedTransfer, TransferError> {
        let input_tree = self.input_tree.ok_or(TransferError::TreeRequired)?;
        let output_tree = self.output_tree.unwrap_or(input_tree);
        let transaction = self.transaction;
        let program_id = self.ring.program_id();
        RingMembership {
            program_id,
            inputs: transaction.inputs(),
            outputs: transaction.outputs(),
        }
        .validate()?;
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
        let mut proof_inputs = transaction.encrypt_with_viewing_key(&sender, &tx_viewing_key)?;
        frame_dummy_outputs(&mut proof_inputs)?;
        proof_inputs.external_data.messages = vec![auditor_message.to_message_data(&auditor_pk)];
        // RING_TRANSACT is folded into external_data_hash and from there into
        // private_tx_hash, so it must be bound before anything hashes external data.
        proof_inputs.external_data.instruction_discriminator = RING_TRANSACT;

        Ok(StagedTransfer {
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
        })
    }
}

/// A policy ring proves the folded statement over its entries-tree roots, an
/// audit-only ring proves the audit statement alone.
enum Tier {
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

    fn policy_tier<I: Rpc, R: Rpc>(
        &self,
        environment: &TransferProofEnvironment<'_, I, R>,
    ) -> Result<Tier, TransferError> {
        let policy_config = self
            .ring
            .read_policy_config(environment.rpc)?
            .ok_or(TransferError::MissingPolicyConfig)?;
        let table = policy_config_table(&policy_config)?;
        let witness = self
            .policy_inputs(&table, &policy_config)
            .build(environment.indexer, environment.rpc)?;
        Ok(Tier::policy(&policy_config, witness))
    }

    async fn policy_tier_async<I: AsyncRpc, R: AsyncRpc>(
        &self,
        environment: &AsyncTransferProofEnvironment<'_, I, R>,
    ) -> Result<Tier, TransferError> {
        let policy_config = self
            .ring
            .read_policy_config_async(environment.rpc)
            .await?
            .ok_or(TransferError::MissingPolicyConfig)?;
        let table = policy_config_table(&policy_config)?;
        let witness = self
            .policy_inputs(&table, &policy_config)
            .build_async(environment.indexer, environment.rpc)
            .await?;
        Ok(Tier::policy(&policy_config, witness))
    }

    fn policy_inputs<'s>(
        &'s self,
        policy: &'s RuleTable,
        policy_config: &'s PolicyConfig,
    ) -> CustomRingWitnessInput<'s> {
        CustomRingWitnessInput {
            policy,
            policy_config,
            inputs: &self.proof_inputs.input_utxos,
            outputs: &self.proof_inputs.output_utxos,
            output_tree_id: self.proof_inputs.output_tree_id,
        }
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
        inputs: Vec<TransferInputUtxo>,
        allow_dummy_inputs: bool,
        tier: Tier,
    ) -> Result<(TierRequest, WitnessedTransfer), TransferError> {
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
            allow_dummy_inputs,
            ring_program_id: Some(self.program_id),
            shape: tx_shape,
        }
        .build()?;
        // The witness leaves assembly with every real input's nullifier secret
        // absent. The sender's authority fills in the ones it owns and rejects
        // an input whose nullifier its secret does not derive; the prover
        // request refuses anything still absent after that.
        if let Some(authority) = self.nullifier_key.as_ref() {
            authority.complete_inputs(&mut ring_result.inputs.inputs)?;
        }
        let private_tx_hash = ring_result.private_tx_hash.try_into()?;
        let request = match tier {
            Tier::Base => TierRequest::Base(self.pending_proof.finish_base(private_tx_hash)?),
            Tier::Policy {
                policy_hash,
                entries_tree,
                witness,
            } => {
                let external_data_hash = self
                    .proof_inputs
                    .external_data
                    .hash()
                    .map_err(|_| TransferError::PolicyHashing)?;
                let roots = witness.roots;
                let private_tx_blinding = self.proof_inputs.private_tx_blinding()?;
                let request = self.pending_proof.finish(
                    private_tx_hash,
                    &external_data_hash,
                    &private_tx_blinding,
                    *witness,
                    &policy_hash,
                )?;
                TierRequest::Policy {
                    request: Box::new(request),
                    entries_tree,
                    roots,
                }
            }
        };
        Ok((
            request,
            WitnessedTransfer {
                tx_viewing_key: self.tx_viewing_key,
                proof_inputs: self.proof_inputs,
                ring_result,
                payer: self.payer,
                input_tree: self.input_tree,
                output_tree: self.output_tree,
                interface_transfer_accounts: self.interface_transfer_accounts,
                ring: self.ring,
            },
        ))
    }
}

/// The tier's prover request, with the accounts and roots the instruction binds
/// for it.
enum TierRequest {
    Base(CustomRingBaseProofRequest),
    Policy {
        request: Box<CustomRingPolicyProofRequest>,
        entries_tree: Address,
        roots: TransactRoots,
    },
}

impl ProveRequest for TierRequest {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        match self {
            Self::Base(request) => request.body(),
            Self::Policy { request, .. } => request.body(),
        }
    }

    fn delivery(&self) -> Delivery {
        match self {
            Self::Base(request) => request.delivery(),
            Self::Policy { request, .. } => request.delivery(),
        }
    }
}

impl TierRequest {
    fn proven(self, proof: Proof) -> Result<TierProof, TransferError> {
        let proof = to_instruction_proof(proof)?;
        Ok(match self {
            Self::Base(_) => TierProof::Base(proof),
            Self::Policy {
                entries_tree,
                roots,
                ..
            } => TierProof::Policy {
                proof,
                entries_tree,
                roots,
            },
        })
    }
}

/// The tier's proof in the instruction's wire encoding.
enum TierProof {
    Base(CustomRingProof),
    Policy {
        proof: CustomRingProof,
        entries_tree: Address,
        roots: TransactRoots,
    },
}

/// Both witnesses built and the auditor encryption closed over the transfer's
/// `private_tx_hash`. Only the two proofs are outstanding.
struct WitnessedTransfer {
    tx_viewing_key: ViewingKey,
    proof_inputs: SppProofInputs,
    ring_result: RingTransferProofResult,
    payer: Address,
    input_tree: Address,
    output_tree: Address,
    interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    ring: CustomRing,
}

impl WitnessedTransfer {
    /// The SPP transfer witness to prove.
    fn spp(&self) -> &TransferInputs {
        &self.ring_result.inputs
    }

    fn finish(
        self,
        spp_proof: TransactProof,
        ring: TierProof,
    ) -> Result<ProvenTransfer, TransferError> {
        let (proof, entries_tree, state_root_index, nullifier_root_index) = match ring {
            TierProof::Base(proof) => (proof, None, 0, 0),
            TierProof::Policy {
                proof,
                entries_tree,
                roots,
            } => (
                proof,
                Some(entries_tree),
                roots.state_index,
                roots.nullifier_index,
            ),
        };
        Ok(ProvenTransfer {
            tx_viewing_key: self.tx_viewing_key,
            data: RingEddsaInstructionData {
                proof_inputs: &self.proof_inputs,
                result: &self.ring_result,
                proof: spp_proof,
            }
            .assemble()?,
            proof,
            owner_signers: self.proof_inputs.owner_signer_pubkeys()?,
            interface_transfer_accounts: self.interface_transfer_accounts,
            state_root_index,
            nullifier_root_index,
            payer: self.payer,
            input_tree: self.input_tree,
            output_tree: self.output_tree,
            entries_tree,
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
            owner_signers: self.owner_signers.clone(),
            interface_transfer_accounts: self.interface_transfer_accounts.clone(),
            proof: self.proof,
            transact: self.data.clone(),
            state_root_index: self.state_root_index,
            nullifier_root_index: self.nullifier_root_index,
        }
        .instruction()
        .map_err(Into::into)
    }
}

impl RingDeposit<'_> {
    pub fn send<R: Rpc>(self, rpc: &R) -> Result<RingDepositReceipt, DepositError> {
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
        let ix = Deposit {
            ring: self.ring,
            tree: self.tree,
            depositor: self.payer.pubkey(),
            deposits: vec![deposit],
        }
        .instruction()?;
        let signature = rpc.create_and_send_transaction(
            core::slice::from_ref(&ix),
            self.payer.pubkey(),
            &[self.payer],
            ComputeBudgetConfig::for_instruction_count(1),
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
    Ok(read_tree_state(rpc, tree)?.tree_id)
}

pub async fn tree_id_async<R: AsyncRpc>(rpc: &R, tree: Address) -> Result<u16, TransferError> {
    Ok(read_tree_state_async(rpc, tree).await?.tree_id)
}

struct TreeState {
    dummy_input_headroom: u64,
    tree_id: u16,
}

fn read_tree_state<R: Rpc>(rpc: &R, tree: Address) -> Result<TreeState, TransferError> {
    tree_state(rpc.get_account(tree)?, tree)
}

async fn read_tree_state_async<R: AsyncRpc>(
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
        tree_id: tree_account.tree_id(),
    })
}

struct RingMembership<'a> {
    program_id: Address,
    inputs: &'a [WalletUtxo],
    outputs: &'a [SppProofOutputUtxo],
}

impl RingMembership<'_> {
    fn validate(self) -> Result<(), TransferError> {
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
fn frame_dummy_outputs(proof_inputs: &mut SppProofInputs) -> Result<(), TransferError> {
    let templates: Vec<(bool, usize)> = proof_inputs
        .output_utxos
        .iter()
        .zip(&proof_inputs.external_data.outputs)
        .filter(|(output, _)| !output.is_dummy())
        .map(|(output, encoded)| {
            encoded
                .data
                .as_ref()
                .map(|data| (output.ring_program_id.is_some(), data.len()))
                .ok_or(TransferError::InvalidDummyOutput)
        })
        .collect::<Result<_, _>>()?;
    for (output, encoded) in proof_inputs
        .output_utxos
        .iter()
        .zip(&mut proof_inputs.external_data.outputs)
    {
        if !output.is_dummy() {
            continue;
        }
        let in_ring = output.ring_program_id.is_some();
        let (_, encoded_len) = templates
            .iter()
            .find(|(ring, _)| *ring == in_ring)
            .or_else(|| templates.first())
            .copied()
            .ok_or(TransferError::InvalidDummyOutput)?;
        let key = ViewingKey::new().pubkey();
        let ciphertext_len = encoded_len
            .checked_sub(1 + 4 + 1 + key.as_bytes().len())
            .filter(|len| *len > 0)
            .ok_or(TransferError::InvalidDummyOutput)?;
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
struct RingSpendInputs<'a, I> {
    indexer: &'a I,
    tree: Address,
    input_utxos: &'a [SppProofInputUtxo],
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
    async fn load_async(self) -> Result<Vec<TransferInputUtxo>, TransferError> {
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
    fn load(self) -> Result<Vec<TransferInputUtxo>, TransferError> {
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
struct RingEddsaInstructionData<'a> {
    proof_inputs: &'a SppProofInputs,
    result: &'a RingTransferProofResult,
    proof: TransactProof,
}

impl RingEddsaInstructionData<'_> {
    fn assemble(self) -> Result<TransactIxData, TransferError> {
        let n_inputs = self.proof_inputs.check_shape()?.n_inputs();
        let inputs =
            input_utxos_from_nullifiers(&self.result.nullifiers, &self.result.input_tree_indexes)?;
        if inputs.len() != n_inputs {
            return Err(TransferError::IncompleteInputSet);
        }

        let external = &self.proof_inputs.external_data;
        Ok(TransactIxData {
            proof: self.proof,
            expiry_unix_ts: external.expiry_unix_ts,
            private_tx_hash: self.result.private_tx_hash,
            circuit: CircuitId::RingEddsa(
                n_inputs as u8,
                external.outputs.len() as u8,
                N_PUBLIC_SLOTS as u8,
            ),
            inputs,
            tree_contexts: self.result.tree_contexts.clone(),
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
        let mut outputs = prepared.outputs().to_vec();
        RingMembership {
            program_id: ring().program_id(),
            inputs: prepared.inputs(),
            outputs: &outputs,
        }
        .validate()
        .expect("default outputs");
        outputs[1].ring_program_id = Some(ring().program_id());
        RingMembership {
            program_id: ring().program_id(),
            inputs: prepared.inputs(),
            outputs: &outputs,
        }
        .validate()
        .expect("active ring output");
        outputs[1].ring_program_id = Some(Address::new_from_array([9u8; 32]));
        assert!(matches!(
            RingMembership {
                program_id: ring().program_id(),
                inputs: prepared.inputs(),
                outputs: &outputs,
            }
            .validate(),
            Err(TransferError::ForeignRing(_))
        ));
    }

    #[test]
    fn membership_refuses_ring_data_outside_a_ring() {
        let (_sender, prepared) = prepared_transfer(4);
        let mut outputs = prepared.outputs().to_vec();
        outputs[1].ring_data_hash = Some([3u8; 32]);
        assert!(matches!(
            RingMembership {
                program_id: ring().program_id(),
                inputs: prepared.inputs(),
                outputs: &outputs,
            }
            .validate(),
            Err(TransferError::RingDataOutsideRing)
        ));
        outputs[1].ring_program_id = Some(ring().program_id());
        RingMembership {
            program_id: ring().program_id(),
            inputs: prepared.inputs(),
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
        frame_dummy_outputs(&mut proof_inputs).expect("mixed framing");
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
        frame_dummy_outputs(&mut proof_inputs).expect("dummy framing");
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
