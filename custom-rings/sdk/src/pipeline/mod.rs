//! One transfer pipeline for every rail, a rail only stages the transfer and seals its outputs.

mod anonymous;
mod audit;
mod compact;
mod delegate;
mod owner;
mod policy;
mod selection;
mod spp;
#[cfg(test)]
#[path = "../tests/pipeline.rs"]
mod tests;

use custom_ring_interface::{
    compute_unit_limit,
    cosign::CoSignDemand,
    stream::{tag_epoch, SenderCommitment},
    AuditBinding, CustomRingError, CustomRingProof, InputTrees, InstructionTag, ParsedTransact,
    PlainGroth16Proof, RingMode, RingProgramConfig, RingRail, Settlement,
    DELIVERED_AUDIT_CAPACITIES, PACKED_AUDIT_CAPACITIES,
};
use solana_address::Address;
use solana_instruction::Instruction;
use zolana_client::{
    AsyncIndexer, AsyncRpc, AsyncZolanaClient, ClientError, ComputeBudgetConfig, ProofAuthority,
    Shape, TransferInput,
};
use zolana_interface::{instruction::TreeContext, N_PUBLIC_SLOTS};
use zolana_keypair::{NullifierKey, ShieldedAddress, ViewingKey, X25519Pubkey};
use zolana_program::instruction::TransactInterfaceTransferAccounts;
use zolana_ring_transaction::{PublishedSlot, RingDelivery, RingOutputRail};
use zolana_transaction::{
    instructions::transact::{SppProofInputs, SppProofOutputUtxo},
    utxo::SppProofInputUtxo,
};

pub use self::{
    anonymous::{
        Anonymous, AnonymousMove, AnonymousPayment, AnonymousSpendSigner, AnonymousTransfer,
        PendingFirstContact, RingPayment, ANCHOR_DECOYS,
    },
    delegate::{
        DelegateMove, DelegateOutput, DelegatePayment, DelegateTransfer, DelegateTransferInput,
        Delegated,
    },
    owner::{CustomRingTransfer, CustomRingTransferInput, Owner},
};

pub(crate) use self::anonymous::HiddenOwner;

use self::{
    anonymous::{AnonymousShape, AnonymousSpend},
    audit::{AnonymousStatement, AuditProving, AuditSeal, SealedAudit},
    compact::{OwnedOutput, OwnedPolicyProof, TransactAccounts, TransactParts},
    policy::{PolicyInputs, PolicyProving, PolicyRead},
    spp::{Spp, SppWitness},
};
use crate::{
    heap::boxed,
    projection::retry_projection_lag,
    submission::{check_transaction_size, BoundPolicy, BoundState},
    trees::spend_trees,
    CustomRing, CustomRingConfig, RingError,
};

mod sealed {
    pub trait Sealed {}
}

/// Who authorizes the spends, the owner, the hidden owner or the delegate.
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
}

#[must_use = "build or submit the proven transfer"]
pub struct ProvenRingTransfer {
    ring: CustomRing,
    config: Box<RingProgramConfig>,
    parts: TransactParts,
    accounts: TransactAccounts,
    bound: BoundState,
    pub tx_viewing_key: ViewingKey,
    /// Padding included.
    pub outputs: Vec<SppProofOutputUtxo>,
    /// The co-signer the config demands, it signs the transaction.
    pub co_signer: Option<Address>,
    /// The anonymous statement's epoch.
    pub epoch: Option<u64>,
    /// Each goes to [`zolana_client::AnonymousRingState::record_first_contact`] once it lands.
    pub first_contacts: Vec<PendingFirstContact>,
}

/// A transfer past its outputs' sealing, ready for its statements.
pub(crate) struct Staged<'a> {
    pub proof_inputs: SppProofInputs,
    pub rail: RingOutputRail,
    pub sender: ShieldedAddress,
    pub authority: TransferAuthority,
    pub owner_signers: Vec<Address>,
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    pub spend: Spend<'a>,
}

pub(crate) enum Spend<'a> {
    Owner,
    Anonymous(Box<AnonymousSpend<'a>>),
    Delegate { delegate: Address },
}

impl Spend<'_> {
    fn rail(&self) -> RingRail {
        match self {
            Self::Owner => RingRail::Confidential,
            Self::Anonymous(_) => RingRail::Anonymous,
            Self::Delegate { .. } => RingRail::Delegate,
        }
    }
}

/// `None` only when every input is padding.
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
    pub fn ring(&self) -> CustomRing {
        self.ring
    }

    pub async fn prove<P: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<P, I>,
    ) -> Result<ProvenRingTransfer, RingError> {
        retry_projection_lag(|| async {
            let assembled = boxed(|| self.assemble(client)).await?;
            boxed(|| assembled.prove(client)).await
        })
        .await
    }

    /// Every chain value is read once.
    pub(crate) async fn assemble<P: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<P, I>,
    ) -> Result<Assembled, RingError> {
        let config = self.ring.require_config(client).await?;
        self.ring.require_active(client).await?;
        let staged = match self.rail.kind() {
            RailKind::Owner(owner) => boxed(|| owner.stage(self.ring, client, &config)).await?,
            RailKind::Anonymous(rail) => boxed(|| rail.stage(self.ring, client, &config)).await?,
            RailKind::Delegated(delegated) => {
                boxed(|| delegated.stage(self.ring, client, &config)).await?
            }
        };
        boxed(|| {
            Pipeline {
                ring: self.ring,
                config: &config,
                staged,
            }
            .assemble(client)
        })
        .await
    }
}

struct Pipeline<'c, 'a> {
    ring: CustomRing,
    config: &'c CustomRingConfig,
    staged: Staged<'a>,
}

/// A transfer whose compact data is final but for its proofs.
pub(crate) struct Assembled {
    ring: CustomRing,
    config: Box<RingProgramConfig>,
    auditor: X25519Pubkey,
    ring_id: [u8; 32],
    proof_inputs: SppProofInputs,
    rail: RingOutputRail,
    sender: ShieldedAddress,
    sealed: SealedAudit,
    spp: Spp,
    published_inputs: usize,
    audit_public_input_hash: [u8; 32],
    anonymous: Option<AnonymousStatement>,
    policy: Option<PolicyInputs>,
    private_tx_hash: [u8; 32],
    private_tx_blinding: [u8; 32],
    policy_sender: [u8; 32],
    sender_pk_hash: [u8; 32],
    public_assets: [[u8; 32]; N_PUBLIC_SLOTS],
    public_amount_fields: [[u8; 32]; N_PUBLIC_SLOTS],
    parts: TransactParts,
    accounts: TransactAccounts,
    co_signer: Option<Address>,
    epoch: Option<u64>,
    bound: BoundState,
    first_contacts: Vec<PendingFirstContact>,
}

impl Pipeline<'_, '_> {
    async fn assemble<P: AsyncRpc, I: AsyncIndexer>(
        self,
        client: &AsyncZolanaClient<P, I>,
    ) -> Result<Assembled, RingError> {
        let Staged {
            mut proof_inputs,
            rail,
            sender,
            authority,
            owner_signers,
            interface_transfer_accounts,
            spend,
        } = self.staged;
        let program = self.ring.program_id();
        let ring_rail = spend.rail();
        // The compact data carries a u32 expiry, an unbounded one keeps its farthest value.
        let expiry_unix_ts =
            u32::try_from(proof_inputs.external_data.expiry_unix_ts).unwrap_or(u32::MAX);
        proof_inputs.external_data.expiry_unix_ts = u64::from(expiry_unix_ts);
        check_distinct(&proof_inputs.input_utxos)?;
        check_membership(
            program,
            &proof_inputs.input_utxos,
            &proof_inputs.output_utxos,
        )?;
        let trees = spend_trees(
            client,
            &proof_inputs.input_utxos,
            proof_inputs.output_tree_id,
        )
        .await?;
        let shape = proof_inputs.check_shape()?;
        let n_in = shape_byte(shape.n_inputs())?;
        let n_out = shape_byte(shape.n_outputs())?;
        let published_inputs = proof_inputs
            .input_utxos
            .iter()
            .filter(|input| !input.is_compact())
            .count();
        let ring_id = self.ring.ring_id()?;
        let auditor = self.config.auditor_pubkey;
        let key_escrow = self.config.mode == RingMode::Registry;
        let preview = |proof_inputs: &SppProofInputs| -> Result<TransactParts, RingError> {
            Ok(preview_parts(PreviewParts {
                rail: ring_rail,
                key_escrow,
                n_in,
                n_out,
                inputs: proof_inputs,
                published: &rail.published_slots(proof_inputs, &sender)?,
                trees: trees.inputs.len(),
                expiry_unix_ts,
                tx_viewing_u: rail.tx_viewing_key().pubkey().u(),
            }))
        };

        // The auditor message precedes every hash over the external data.
        let unsealed = preview(&proof_inputs)?;
        let sealed = AuditSeal {
            rail: &rail,
            layout: unsealed.data().disclosure_layout()?,
            flags: unsealed.data().audit_layout(),
            published: &rail.published_slots(&proof_inputs, &sender)?,
            inputs: &proof_inputs,
            sender: &sender,
            auditor: &auditor,
        }
        .seal()?;
        proof_inputs.external_data.messages = vec![sealed.message(&auditor)];
        proof_inputs.external_data.instruction_discriminator = ring_rail.spp_tag();

        let public = zolana_transaction::instructions::transact::public_slots(
            &proof_inputs.external_data.interface_transfers,
        )?;
        let public_assets = public.asset_fields()?;
        let public_amounts = public.amounts();
        let public_amount_fields = public.amount_fields()?;
        let private_tx_blinding = proof_inputs.private_tx_blinding()?;
        let sender_pk_hash = sender.signing_pubkey.owner_proof_input_hash()?;
        let policy = match self.config.has_policy {
            true => Some(
                PolicyRead {
                    ring: self.ring,
                    config: self.config,
                    rail: ring_rail,
                    inputs: &proof_inputs,
                    sender: sender_pk_hash,
                    public_assets: &public_assets,
                    public_amounts: &public_amounts,
                }
                .read(client)
                .await?,
            ),
            false => None,
        };
        let approval_required = policy
            .as_ref()
            .is_some_and(|policy| policy.approval_required);
        let transfers = &proof_inputs.external_data.interface_transfers;
        let legs: Vec<_> = transfers
            .iter()
            .map(|transfer| transfer.public_leg())
            .collect();
        let co_signer =
            CoSignDemand::transact(approval_required, &legs).signer(self.config.account())?;
        if co_signer.is_some_and(|co_signer| owner_signers.contains(&co_signer)) {
            return Err(CustomRingError::CoSignerIsOwner.into());
        }
        let (hidden, anonymous) = match &spend {
            Spend::Anonymous(anonymous) => {
                let hidden = anonymous
                    .sign(self.ring, self.config, &proof_inputs)
                    .await?;
                (Some(hidden), Some(anonymous))
            }
            Spend::Owner | Spend::Delegate { .. } => (None, None),
        };
        let anchor = anonymous.and_then(|anonymous| anonymous.bound_anchor());
        let spp = SppWitness {
            ring: program,
            rail: ring_rail,
            inputs: &proof_inputs,
            trees: &trees,
            authority: &authority,
            hidden,
        }
        .build(client)
        .await?;
        let private_tx_hash = spp.private_tx_hash();
        let sender_commitment = match (anonymous.is_some(), &policy) {
            (true, Some(_)) => Some(
                SenderCommitment {
                    sender_pk_hash,
                    private_tx_blinding,
                }
                .derive()?,
            ),
            _ => None,
        };
        let accounts = TransactAccounts {
            payer: proof_inputs.payer,
            input_trees: trees.inputs.clone(),
            output_tree: trees.output,
            owner_signers,
            interface_transfer_accounts,
            registry: self.config.has_policy.then(|| self.ring.registry_pda()),
            curator: policy
                .as_ref()
                .and_then(|policy| policy.curator.map(|curator| curator.address)),
            co_signer,
            delegate: match spend {
                Spend::Delegate { delegate } => Some(delegate),
                Spend::Owner | Spend::Anonymous(_) => None,
            },
            anchor_tree: anchor.map(|anchor| anchor.tree),
        };
        let mut parts = preview(&proof_inputs)?;
        parts.eph_u = sealed.eph_u;
        parts.sealed = sealed.sealed;
        parts.disclosure = sealed.fields.clone();
        parts.private_tx_hash = private_tx_hash;
        parts.approval_required = approval_required;
        parts.policy = policy.as_ref().map(|policy| OwnedPolicyProof {
            proof: zeroed_proof(),
            own_root_index: policy.own.index,
            curator_root_index: policy.curator.map(|curator| curator.root.index),
            sender_commitment,
        });
        if let Some(anonymous) = anonymous {
            parts.anchor = anonymous.anchor_root(accounts.anchor_slot());
            parts.anonymous = Some(compact::OwnedAnonymousProofData {
                commitment: [0; 32],
                commitment_pok: [0; 32],
                // SPP publishes the hidden owner's key exactly when it spends a default-ring note.
                default_owner_tag: parts
                    .full_openings
                    .then(|| sender.signing_pubkey.as_ed25519())
                    .transpose()?,
            });
        }
        let settlements: Vec<_> = transfers
            .iter()
            .map(|transfer| transfer.settlement_accounts())
            .collect();
        let settlement_views: Vec<Settlement<'_>> = settlements
            .iter()
            .map(|[asset_account, user_account]| Settlement {
                asset_account,
                user_account,
            })
            .collect();
        if parts
            .data()
            .external_data_hash(self.config.account(), &settlement_views)?
            != proof_inputs.external_data.hash()?
        {
            return Err(RingError::ExternalDataMismatch);
        }
        let epoch = anonymous.map(|anonymous| anonymous.epoch);
        let first_contact_root = anchor.map_or([0; 32], |anchor| anchor.root);
        let audit_public_input_hash = ParsedTransact::new(parts.data())?
            .audit_statement(AuditBinding {
                ring_id: &ring_id,
                auditor_pubkey: auditor.as_bytes(),
                epoch: epoch.unwrap_or_default(),
                first_contact_root: &first_contact_root,
                key_escrow,
            })?
            .hash()?;
        let statement = anonymous.map(|anonymous| AnonymousStatement {
            private_tx_hash,
            private_tx_blinding,
            sender_commitment: sender_commitment.unwrap_or_default(),
            epoch: anonymous.epoch,
            first_contact_root,
            anchor: anonymous.anchor_witness(),
        });
        let first_contacts = anonymous
            .map(|anonymous| anonymous.first_contacts.clone())
            .unwrap_or_default();
        let bound = BoundState {
            roots: policy
                .iter()
                .flat_map(|policy| {
                    core::iter::once(policy.own).chain(policy.curator.map(|curator| curator.root))
                })
                .collect(),
            policy: policy.as_ref().map(|policy| BoundPolicy {
                ring: self.ring,
                hash: policy.policy_hash,
            }),
            anchor,
            queue: None,
            epoch,
        };
        let assembled = Assembled {
            ring: self.ring,
            config: Box::new(*self.config.account()),
            auditor,
            ring_id,
            policy_sender: match (ring_rail, sender_commitment) {
                (RingRail::Delegate, _) => [0; 32],
                (_, Some(commitment)) => commitment,
                (_, None) => sender_pk_hash,
            },
            proof_inputs,
            rail,
            sender,
            sealed,
            spp,
            published_inputs,
            audit_public_input_hash,
            anonymous: statement,
            policy,
            private_tx_hash,
            private_tx_blinding,
            sender_pk_hash,
            public_assets,
            public_amount_fields,
            parts,
            accounts,
            co_signer,
            epoch,
            bound,
            first_contacts,
        };
        check_transaction_size(
            &assembled.proof_inputs.payer,
            &assembled.instruction()?,
            ComputeBudgetConfig::new(compute_unit_limit(match ring_rail {
                RingRail::Delegate => InstructionTag::DelegateTransact,
                RingRail::Confidential | RingRail::Anonymous => InstructionTag::Transact,
            })),
        )?;
        Ok(assembled)
    }
}

impl Assembled {
    /// The instruction under zeroed proofs, the size of the proven one.
    pub(crate) fn instruction(&self) -> Result<Instruction, RingError> {
        self.accounts
            .instruction(self.ring, &self.config, &self.parts)
    }

    pub(crate) fn audit(&self) -> Result<AuditProving<'_>, RingError> {
        Ok(AuditProving {
            rail: &self.rail,
            sealed: &self.sealed,
            published: self
                .rail
                .published_slots(&self.proof_inputs, &self.sender)?,
            inputs: &self.proof_inputs,
            sender: &self.sender,
            auditor: &self.auditor,
            ring_id: self.ring_id,
            public_input_hash: self.audit_public_input_hash,
            anonymous: self.anonymous.as_ref(),
        })
    }

    async fn prove<P: AsyncRpc, I: AsyncIndexer>(
        self,
        client: &AsyncZolanaClient<P, I>,
    ) -> Result<ProvenRingTransfer, RingError> {
        let audit = self.audit()?;
        let policy_proving = PolicyProving {
            ring_id: self.ring_id,
            rail: self.parts.rail,
            inputs: &self.proof_inputs,
            private_tx_hash: self.private_tx_hash,
            private_tx_blinding: self.private_tx_blinding,
            sender: self.policy_sender,
            sender_pk_hash: self.sender_pk_hash,
            public_assets: self.public_assets,
            public_amount_fields: self.public_amount_fields,
        };
        let policy_proof = async {
            match &self.policy {
                Some(policy) => Ok(Some(policy.prove(client, &policy_proving).await?)),
                None => Ok::<_, RingError>(None),
            }
        };
        // No proof is an input to another, every request goes out at once.
        let (proven_spp, audit_proof, policy_proof) = futures::try_join!(
            boxed(|| self.spp.prove(client, self.published_inputs)),
            boxed(|| audit.prove(client)),
            boxed(|| policy_proof),
        )?;
        let mut parts = self.parts;
        parts.audit_proof = audit_proof;
        if let (Some(owned), Some(proof)) = (parts.policy.as_mut(), policy_proof) {
            owned.proof = proof;
        }
        parts.spp_proof = proven_spp.proof;
        parts.nullifiers = proven_spp.nullifiers;
        parts.input_trees = proven_spp.input_trees;
        if parts.anonymous.is_some() {
            parts.anonymous = proven_spp.anonymous;
        }
        Ok(ProvenRingTransfer {
            ring: self.ring,
            config: self.config,
            bound: self.bound,
            parts,
            accounts: self.accounts,
            tx_viewing_key: self.rail.tx_viewing_key().clone(),
            outputs: self.proof_inputs.output_utxos,
            co_signer: self.co_signer,
            epoch: self.epoch,
            first_contacts: self.first_contacts,
        })
    }
}

impl ProvenRingTransfer {
    pub(crate) fn bound(&self) -> BoundState {
        self.bound.clone()
    }

    /// The instruction landing in the proof's own epoch.
    pub fn instruction(&self) -> Result<Instruction, RingError> {
        self.accounts
            .instruction(self.ring, &self.config, &self.parts)
    }

    /// An anonymous transfer at `slot` one epoch late names the previous epoch, a later one fails.
    pub fn instruction_at(&self, slot: u64) -> Result<Instruction, RingError> {
        let Some(proof_epoch) = self.epoch else {
            return self.instruction();
        };
        let current_epoch = tag_epoch(slot);
        let previous_epoch = match current_epoch.checked_sub(proof_epoch) {
            Some(0) => false,
            Some(1) => true,
            _ => {
                return Err(RingError::EpochPassed {
                    proof_epoch,
                    current_epoch,
                })
            }
        };
        let parts = TransactParts {
            previous_epoch,
            ..self.parts.clone()
        };
        self.accounts.instruction(self.ring, &self.config, &parts)
    }
}

/// Whether `rail` keys a transfer of `shape` publishing every input, none a default-ring UTXO.
pub fn shape_keyed(rail: RingRail, shape: Shape) -> bool {
    let outputs = shape.n_outputs();
    let capacity =
        PACKED_AUDIT_CAPACITIES.contains(&outputs) || DELIVERED_AUDIT_CAPACITIES.contains(&outputs);
    match rail {
        RingRail::Confidential => capacity && shape.is_supported(),
        RingRail::Delegate => capacity && shape.is_ring_authority(),
        RingRail::Anonymous => AnonymousShape {
            shape,
            spends_default_ring: false,
        }
        .keyed(),
    }
}

/// The compact data before any proof, sized and hashed as the proven one.
struct PreviewParts<'a> {
    rail: RingRail,
    key_escrow: bool,
    n_in: u8,
    n_out: u8,
    inputs: &'a SppProofInputs,
    published: &'a [PublishedSlot<'a>],
    trees: usize,
    expiry_unix_ts: u32,
    tx_viewing_u: [u8; 32],
}

fn preview_parts(preview: PreviewParts<'_>) -> TransactParts {
    let external = &preview.inputs.external_data;
    let nullifiers = preview
        .inputs
        .input_utxos
        .iter()
        .filter(|input| !input.is_compact())
        .map(SppProofInputUtxo::nullifier)
        .collect();
    let context = TreeContext {
        utxo_tree_root_index: 0,
        nullifier_tree_root_index: 0,
    };
    TransactParts {
        rail: preview.rail,
        n_in: preview.n_in,
        n_out: preview.n_out,
        audit_proof: zeroed_proof(),
        policy: None,
        approval_required: false,
        previous_epoch: false,
        anchor: None,
        expiry_unix_ts: preview.expiry_unix_ts,
        tx_viewing_u: preview.tx_viewing_u,
        salt: external.salt,
        interface_transfers: external
            .interface_transfers
            .iter()
            .map(|transfer| transfer.interface_transfer())
            .collect(),
        data_hash: external.data_hash,
        ring_data_hash: external.ring_data_hash,
        data_free: preview
            .inputs
            .output_utxos
            .iter()
            .all(|output| output.data.is_empty()),
        key_escrow: preview.key_escrow,
        full_openings: preview.rail == RingRail::Anonymous
            && spends_default_ring(&preview.inputs.input_utxos),
        outputs: preview
            .published
            .iter()
            .map(|slot| OwnedOutput::of(slot.wire))
            .collect(),
        eph_u: [0; 32],
        sealed: [0; 32],
        disclosure: Vec::new(),
        private_tx_hash: [0; 32],
        anonymous: None,
        spp_proof: PlainGroth16Proof {
            proof_a: [0; 32],
            proof_b: [0; 64],
            proof_c: [0; 32],
        },
        nullifiers,
        input_trees: match preview.trees {
            1 => InputTrees::One(context),
            _ => InputTrees::Two {
                first: context,
                second: context,
                second_inputs: 0,
            },
        },
    }
}

fn zeroed_proof() -> CustomRingProof {
    bytemuck::Zeroable::zeroed()
}

fn spends_default_ring(inputs: &[SppProofInputUtxo]) -> bool {
    inputs
        .iter()
        .any(|input| !input.is_dummy() && input.utxo.ring_program_id.is_none())
}

fn packed_or_delivered(outputs: usize, rail: &'static str) -> Result<RingDelivery, RingError> {
    match outputs {
        n if PACKED_AUDIT_CAPACITIES.contains(&n) => Ok(RingDelivery::Packed),
        n if DELIVERED_AUDIT_CAPACITIES.contains(&n) => Ok(RingDelivery::Delivered),
        _ => Err(RingError::ShapeUnkeyed { rail }),
    }
}

fn shape_byte(count: usize) -> Result<u8, RingError> {
    u8::try_from(count).map_err(|_| RingError::ShapeUnkeyed { rail: "spp" })
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

/// Every ring field names the transfer's ring, only a ring note carries ring data.
pub(crate) fn check_membership(
    program: Address,
    inputs: &[SppProofInputUtxo],
    outputs: &[SppProofOutputUtxo],
) -> Result<(), RingError> {
    let slots = inputs
        .iter()
        .map(|input| (input.utxo.ring_program_id, input.ring_data_hash))
        .chain(
            outputs
                .iter()
                .map(|output| (output.ring_program_id, output.ring_data_hash)),
        );
    for (ring, data) in slots {
        match ring {
            Some(ring) if ring != program => return Err(RingError::ForeignRing(ring)),
            None if data.is_some() => return Err(RingError::RingDataOutsideRing),
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn transaction_key(
    sender: &(dyn zolana_transaction::ShieldedKeys + Send + Sync),
    first_nullifier: [u8; 32],
) -> Result<ViewingKey, RingError> {
    let keys = sender.transaction_keys(&[zolana_transaction::TransactionKeyRequest {
        viewing_pubkey: sender.address()?.viewing_pubkey,
        first_nullifier,
    }])?;
    Ok(zolana_transaction::exactly_one(keys)?)
}
