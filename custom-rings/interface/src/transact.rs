//! The compact `Transact` and `DelegateTransact` data, read in place and expanded into
//! the SPP `TransactIxData` the SPP proof's external data hash covers.

use solana_address::Address;
use wincode::{containers, len::FixIntLen, Serialize};
use zolana_event::{
    encode_confidential_output, encode_ring_anonymous_output,
    encode_ring_confidential_delivered_output, encode_ring_confidential_packed_output,
    CONFIDENTIAL_DATA_FREE_BODY_LEN, RECIPIENT_KEY_LEN, RING_DELIVERED_BODY_LEN,
    RING_PACKED_DATA_FREE_BODY_LEN,
};
use zolana_hasher::{
    primitives::{hash_bytes, pack_be},
    HasherError,
};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{AnonymousRingEddsaProofData, Bsb22Commitment},
        tag::{RING_AUTHORITY_TRANSACT, RING_TRANSACT},
        CircuitId, ExternalDataPreimage, InputUtxo, InterfaceTransfer, MessageData, OwnerTag,
        TransactIxData, TransactIxDataRef, TransactOutput, TransactProof, TreeContext,
    },
    shape::{Shape, SPP_SUPPORTED_SHAPES},
    N_PUBLIC_SLOTS,
};

use crate::{
    bytes::Bytes,
    disclosure::{
        AnonymousAuditKey, AnonymousLayout, AnonymousSpend, AuditLayout, DeliveredLayout,
        DisclosureLayout, PackedLayout, DELIVERED_AUDIT_CAPACITIES, PACKED_AUDIT_CAPACITIES,
    },
    error::CustomRingError,
    statement::{AnonymousAudit, AuditHead, AuditKind, AuditStatement, PolicyKey},
    stream::{tag_epoch, RingTag, TAG_LEN},
    tagged_x25519, AuditorMessage, CustomRingProof, InstructionTag, MemberRegistry,
    PlainGroth16Proof, RingMode, RingProgramConfig, AUDIT_CIPHERTEXT_LEN, TAGGED_X25519_KEY_LEN,
};

const ZERO_FIELD: [u8; 32] = [0; 32];
/// The scheme 11 ciphertext after the recipient key of an output with no data.
const DATA_FREE_PACKED_CIPHERTEXT_LEN: usize = RING_PACKED_DATA_FREE_BODY_LEN - RECIPIENT_KEY_LEN;
/// Key support reads the shape alone.
const NO_PROOF_DATA: AnonymousRingEddsaProofData = AnonymousRingEddsaProofData {
    bsb22_commitment: Bsb22Commitment {
        commitment: ZERO_FIELD,
        commitment_pok: ZERO_FIELD,
    },
    default_owner_tag: None,
};

/// The program rail the data serves, fixed by the instruction tag and the ring mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingRail {
    Confidential,
    Anonymous,
    /// `DelegateTransact`, the SPP authority rail of a policy ring in registry mode.
    Delegate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RailSigner {
    /// The confidential rail's owner signer run.
    Owners,
    /// The anonymous rail, the payer alone signs.
    Payer,
    Delegate(Address),
}

impl RailSigner {
    pub fn new(tag: InstructionTag, config: &RingProgramConfig) -> Result<Self, CustomRingError> {
        match RingRail::of(tag, config.mode()?)? {
            RingRail::Anonymous => Ok(Self::Payer),
            RingRail::Confidential => Ok(Self::Owners),
            // Only SetDelegate writes a delegate, together with Registry mode on a policy ring.
            RingRail::Delegate => config
                .delegate()
                .copied()
                .map(Self::Delegate)
                .ok_or(CustomRingError::DelegateDisabled),
        }
    }

    pub const fn rail(self) -> RingRail {
        match self {
            Self::Owners => RingRail::Confidential,
            Self::Payer => RingRail::Anonymous,
            Self::Delegate(_) => RingRail::Delegate,
        }
    }
}

impl RingRail {
    pub fn new(tag: InstructionTag, config: &RingProgramConfig) -> Result<Self, CustomRingError> {
        RailSigner::new(tag, config).map(RailSigner::rail)
    }

    pub fn of(tag: InstructionTag, mode: RingMode) -> Result<Self, CustomRingError> {
        match (tag, mode) {
            (InstructionTag::Transact, RingMode::Anonymous) => Ok(Self::Anonymous),
            (InstructionTag::Transact, RingMode::Off | RingMode::Registry) => {
                Ok(Self::Confidential)
            }
            (InstructionTag::DelegateTransact, RingMode::Anonymous) => {
                Err(CustomRingError::AnonymousRingRefused)
            }
            (InstructionTag::DelegateTransact, RingMode::Off | RingMode::Registry) => {
                Ok(Self::Delegate)
            }
            _ => Err(CustomRingError::InvalidInstructionData),
        }
    }

    pub const fn spp_tag(self) -> u8 {
        match self {
            Self::Confidential | Self::Anonymous => RING_TRANSACT,
            Self::Delegate => RING_AUTHORITY_TRANSACT,
        }
    }

    pub const fn policy_key(self) -> PolicyKey {
        match self {
            Self::Confidential => PolicyKey::Member { anonymous: false },
            Self::Anonymous => PolicyKey::Member { anonymous: true },
            Self::Delegate => PolicyKey::Delegate,
        }
    }

    fn circuit(self, n_in: u8, n_out: u8, proof_data: AnonymousRingEddsaProofData) -> CircuitId {
        let slots = N_PUBLIC_SLOTS as u8;
        match self {
            Self::Confidential => CircuitId::ConfidentialRingEddsa(n_in, n_out, slots),
            Self::Anonymous => CircuitId::AnonymousRingEddsa(n_in, n_out, slots, proof_data),
            Self::Delegate => CircuitId::RingAuthority(n_in, n_out, slots),
        }
    }

    /// The audit key the header names, before the output count is read.
    fn audit_shape(self, header: &FrameHeader) -> Result<AuditShape, CustomRingError> {
        let supported = self
            .circuit(header.n_in, header.n_out, NO_PROOF_DATA)
            .is_supported();
        let (n_out, inputs) = (usize::from(header.n_out), usize::from(header.input_count));
        let audit = match self {
            Self::Confidential | Self::Delegate if PACKED_AUDIT_CAPACITIES.contains(&n_out) => {
                Some(AuditShape::Packed { capacity: n_out })
            }
            Self::Confidential | Self::Delegate if DELIVERED_AUDIT_CAPACITIES.contains(&n_out) => {
                Some(AuditShape::Delivered { outputs: n_out })
            }
            Self::Anonymous => AnonymousSpend {
                inputs,
                outputs: n_out,
                spends_default_ring: header.flags.full_openings,
            }
            .audit_key()
            .map(|key| AuditShape::Anonymous {
                key,
                inputs,
                outputs: n_out,
            }),
            Self::Confidential | Self::Delegate => None,
        };
        let audit = audit
            .filter(|_| supported)
            .ok_or(CustomRingError::RingShapeUnkeyed)?;
        if inputs == 0 || inputs > usize::from(header.n_in) {
            return Err(CustomRingError::RingTransactLength);
        }
        Ok(audit)
    }
}

#[derive(Clone, Copy)]
enum AuditShape {
    Packed {
        capacity: usize,
    },
    Delivered {
        outputs: usize,
    },
    Anonymous {
        key: AnonymousAuditKey,
        inputs: usize,
        outputs: usize,
    },
}

impl AuditShape {
    /// Every delivered and anonymous slot is published, a packed transfer publishes a prefix.
    const fn fixed_outputs(self) -> Option<usize> {
        match self {
            Self::Packed { .. } => None,
            Self::Delivered { outputs } | Self::Anonymous { outputs, .. } => Some(outputs),
        }
    }

    fn layout(
        self,
        published: usize,
        flags: AuditLayout,
    ) -> Result<DisclosureLayout, CustomRingError> {
        let layout = match self {
            Self::Packed { capacity } if (1..=capacity).contains(&published) => {
                DisclosureLayout::Packed(PackedLayout {
                    outputs: published,
                    exits: flags.exits,
                    key_escrow: flags.key_escrow,
                    data_free: flags.data_free,
                })
            }
            Self::Delivered { outputs } if published == outputs => {
                DisclosureLayout::Delivered(DeliveredLayout {
                    outputs,
                    exits: flags.exits,
                    key_escrow: flags.key_escrow,
                })
            }
            Self::Anonymous {
                key,
                inputs,
                outputs,
            } if published == outputs => DisclosureLayout::Anonymous(AnonymousLayout {
                key,
                inputs,
                outputs,
                exits: flags.exits,
            }),
            _ => return Err(CustomRingError::RingTransactLength),
        };
        Ok(layout)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyProof<'a> {
    pub proof: &'a CustomRingProof,
    pub own_root_index: u8,
    /// Set exactly when a source names the curator registry.
    pub curator_root_index: Option<u8>,
    /// Set exactly on the anonymous rail.
    pub sender_commitment: Option<&'a [u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyBinding<'a> {
    pub proof: PolicyProof<'a>,
    pub policy_hash: [u8; 32],
    pub own_root: [u8; 32],
    pub curator: Option<CuratorRoot>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CuratorRoot {
    pub registry: Address,
    pub root_index: u8,
}

/// The SPP state tree root a pair-anchored slot's first contact opens under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorRoot {
    /// Index into the instruction's accounts.
    pub tree: u8,
    /// Index into the tree's UTXO root history.
    pub root_index: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnonymousProofData<'a> {
    pub commitment: &'a [u8; 32],
    pub commitment_pok: &'a [u8; 32],
    /// The hidden owner's default-ring key.
    pub default_owner_tag: Option<&'a [u8; 32]>,
}

/// The tree contexts inputs spend from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputTrees {
    One(TreeContext),
    /// Bit `i` of `second_inputs` spends input `i` from `second`.
    Two {
        first: TreeContext,
        second: TreeContext,
        second_inputs: u64,
    },
}

impl InputTrees {
    fn tree_index(self, input: usize) -> u8 {
        match self {
            Self::One(_) => 0,
            Self::Two { second_inputs, .. } => ((second_inputs >> input) & 1) as u8,
        }
    }

    fn contexts(self) -> Vec<TreeContext> {
        match self {
            Self::One(context) => vec![context],
            Self::Two { first, second, .. } => vec![first, second],
        }
    }
}

/// One published output slot without its SPP framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingOutput<'a> {
    /// Capacity 2 and 4 of the confidential and delegate rails, scheme 11.
    Packed {
        hash: &'a [u8; 32],
        u: &'a [u8; 32],
        ciphertext: &'a [u8],
    },
    /// Capacity 8 and 16 of the confidential and delegate rails, scheme 10.
    Delivered {
        hash: &'a [u8; 32],
        u: &'a [u8; 32],
        body: &'a [u8; RING_DELIVERED_BODY_LEN],
    },
    /// Scheme 9 under the owner tag `0^16 || tag`.
    Anonymous {
        hash: &'a [u8; 32],
        tag: RingTag,
        body: &'a [u8; RING_DELIVERED_BODY_LEN],
    },
    /// A default-ring output, scheme 3 under its own owner tag.
    Exit {
        hash: &'a [u8; 32],
        owner_tag: &'a [u8; 32],
        payload: &'a [u8],
    },
}

impl<'a> RingOutput<'a> {
    pub const fn hash(&self) -> &'a [u8; 32] {
        match self {
            Self::Packed { hash, .. }
            | Self::Delivered { hash, .. }
            | Self::Anonymous { hash, .. }
            | Self::Exit { hash, .. } => hash,
        }
    }

    pub const fn is_exit(&self) -> bool {
        matches!(self, Self::Exit { .. })
    }

    /// `hash_bytes(body)` of a delivered or anonymous slot, zero for any other.
    pub fn body_hash(&self) -> Result<[u8; 32], HasherError> {
        match self {
            Self::Delivered { body, .. } | Self::Anonymous { body, .. } => hash_bytes(body),
            Self::Packed { .. } | Self::Exit { .. } => Ok(ZERO_FIELD),
        }
    }

    /// `pack_be(u)` of a delivered slot, zeros for any other.
    pub fn recipient_key_fields(&self) -> [[u8; 32]; 2] {
        match self {
            Self::Delivered { u, .. } => pack_be(u),
            _ => [ZERO_FIELD; 2],
        }
    }

    /// `0^16 || tag` of an anonymous slot, zero for any other.
    pub fn tag_field(&self) -> [u8; 32] {
        match self {
            Self::Anonymous { tag, .. } => tag.field(),
            _ => ZERO_FIELD,
        }
    }

    /// The SPP output, the owner tag and the scheme framing rebuilt from the slot.
    pub fn transact_output(&self) -> TransactOutput {
        let (owner_tag, data) = match *self {
            Self::Packed { u, ciphertext, .. } => (
                *u,
                encode_ring_confidential_packed_output(&tagged_x25519(u), ciphertext),
            ),
            Self::Delivered { u, body, .. } => {
                (*u, encode_ring_confidential_delivered_output(body))
            }
            Self::Anonymous { tag, body, .. } => (tag.field(), encode_ring_anonymous_output(body)),
            Self::Exit {
                owner_tag, payload, ..
            } => (*owner_tag, encode_confidential_output(payload)),
        };
        TransactOutput {
            utxo_hash: *self.hash(),
            owner_tag: OwnerTag::Inline(owner_tag),
            data: Some(data),
        }
    }

    /// Whether the slot uses the output encoding `layout` gives ring outputs.
    fn fits(&self, layout: DisclosureLayout) -> bool {
        matches!(
            (self, layout),
            (Self::Exit { .. }, _)
                | (Self::Packed { .. }, DisclosureLayout::Packed { .. })
                | (Self::Delivered { .. }, DisclosureLayout::Delivered { .. })
                | (Self::Anonymous { .. }, DisclosureLayout::Anonymous { .. })
        )
    }
}

#[derive(Clone, Copy)]
struct SlotFrame {
    layout: DisclosureLayout,
    /// Packed ciphertexts and exit payloads take their data-free lengths without a prefix.
    data_free: bool,
}

impl SlotFrame {
    fn read_exit<'a>(self, bytes: &mut Bytes<'a>) -> Result<RingOutput<'a>, CustomRingError> {
        Ok(RingOutput::Exit {
            hash: bytes.array()?,
            owner_tag: bytes.array()?,
            payload: self.read_body(bytes, CONFIDENTIAL_DATA_FREE_BODY_LEN)?,
        })
    }

    fn read_ring<'a>(self, bytes: &mut Bytes<'a>) -> Result<RingOutput<'a>, CustomRingError> {
        let hash = bytes.array()?;
        Ok(match self.layout {
            DisclosureLayout::Packed { .. } => RingOutput::Packed {
                hash,
                u: bytes.array()?,
                ciphertext: self.read_body(bytes, DATA_FREE_PACKED_CIPHERTEXT_LEN)?,
            },
            DisclosureLayout::Delivered { .. } => RingOutput::Delivered {
                hash,
                u: bytes.array()?,
                body: bytes.array()?,
            },
            DisclosureLayout::Anonymous { .. } => RingOutput::Anonymous {
                hash,
                tag: RingTag::from_bytes(*bytes.array::<TAG_LEN>()?),
                body: bytes.array()?,
            },
        })
    }

    fn write(self, output: &RingOutput<'_>, out: &mut Vec<u8>) -> Result<(), CustomRingError> {
        out.extend_from_slice(output.hash());
        match output {
            RingOutput::Packed { u, ciphertext, .. } => {
                out.extend_from_slice(*u);
                self.write_body(out, ciphertext, DATA_FREE_PACKED_CIPHERTEXT_LEN)
            }
            RingOutput::Delivered { u, body, .. } => {
                out.extend_from_slice(*u);
                out.extend_from_slice(*body);
                Ok(())
            }
            RingOutput::Anonymous { tag, body, .. } => {
                out.extend_from_slice(tag.as_bytes());
                out.extend_from_slice(*body);
                Ok(())
            }
            RingOutput::Exit {
                owner_tag, payload, ..
            } => {
                out.extend_from_slice(*owner_tag);
                self.write_body(out, payload, CONFIDENTIAL_DATA_FREE_BODY_LEN)
            }
        }
    }

    fn read_body<'a>(
        self,
        bytes: &mut Bytes<'a>,
        data_free_len: usize,
    ) -> Result<&'a [u8], CustomRingError> {
        match self.data_free {
            true => bytes.take(data_free_len),
            false => bytes.sized(),
        }
    }

    fn write_body(
        self,
        out: &mut Vec<u8>,
        body: &[u8],
        data_free_len: usize,
    ) -> Result<(), CustomRingError> {
        match self.data_free {
            true if body.len() == data_free_len => {
                out.extend_from_slice(body);
                Ok(())
            }
            true => Err(CustomRingError::DataFreeBodyLength),
            false => push_sized(out, body),
        }
    }
}

/// One public leg's committed accounts, the asset account then the user account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settlement<'a> {
    pub asset_account: &'a [u8; 32],
    pub user_account: &'a [u8; 32],
}

/// The layout is always the one the data's own frame selects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedTransact<'a> {
    data: RingTransactData<'a>,
    layout: DisclosureLayout,
}

impl<'a> ParsedTransact<'a> {
    pub fn new(data: RingTransactData<'a>) -> Result<Self, CustomRingError> {
        let layout = data.disclosure_layout()?;
        Ok(Self { data, layout })
    }

    pub const fn data(&self) -> &RingTransactData<'a> {
        &self.data
    }

    pub fn into_data(self) -> RingTransactData<'a> {
        self.data
    }

    pub const fn layout(&self) -> DisclosureLayout {
        self.layout
    }

    /// The statement the audit proof is verified against, a key escrow flag off the ring mode
    /// refused.
    pub fn audit_statement<'s>(
        &'s self,
        binding: AuditBinding<'s>,
    ) -> Result<AuditStatement<'s>, CustomRingError> {
        let data = &self.data;
        if binding.key_escrow != data.key_escrow {
            return Err(CustomRingError::FlagNotAllowed);
        }
        let kind = match self.layout {
            DisclosureLayout::Packed(_) => AuditKind::Packed,
            DisclosureLayout::Delivered(_) => AuditKind::Delivered,
            DisclosureLayout::Anonymous(_) => AuditKind::Anonymous(AnonymousAudit {
                private_tx_hash: data.private_tx_hash,
                epoch: binding.epoch,
                first_contact_root: binding.first_contact_root,
                sender_commitment: data.sender_commitment(),
            }),
        };
        Ok(AuditStatement {
            head: AuditHead {
                first_nullifier: data.first_nullifier()?,
                ring_id: binding.ring_id,
                tx_viewing_u: data.tx_viewing_u,
                auditor_pubkey: binding.auditor_pubkey,
                eph_u: data.eph_u,
                sealed: data.sealed,
                salt: data.salt,
                layout: data.audit_layout(),
            },
            outputs: &data.outputs,
            disclosure: data.disclosure,
            kind,
        })
    }
}

/// What the program supplies beside the data for the audit statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditBinding<'a> {
    /// `hash_bytes` of the ring program id.
    pub ring_id: &'a [u8; 32],
    pub auditor_pubkey: &'a [u8; TAGGED_X25519_KEY_LEN],
    /// The anonymous rail's statement epoch.
    pub epoch: u64,
    /// The anonymous rail's first-contact root, zero without an anchor.
    pub first_contact_root: &'a [u8; 32],
    /// The ring mode escrows every output nullifier key, the frame flag has to agree.
    pub key_escrow: bool,
}

/// The data of `Transact` and `DelegateTransact`, every count ahead of the sections it sizes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingTransactData<'a> {
    pub rail: RingRail,
    /// SPP shape inputs.
    pub n_in: u8,
    /// SPP shape outputs.
    pub n_out: u8,
    pub audit_proof: &'a CustomRingProof,
    /// Present exactly on a policy ring.
    pub policy: Option<PolicyProof<'a>>,
    pub approval_required: bool,
    /// The anonymous rail's statement epoch is the one before the landing slot's.
    pub previous_epoch: bool,
    pub anchor: Option<AnchorRoot>,
    pub expiry_unix_ts: u32,
    pub tx_viewing_u: &'a [u8; 32],
    /// Random per attempt, a resend under the same first nullifier reuses no pad or keystream.
    pub salt: &'a [u8; 16],
    pub interface_transfers: Vec<InterfaceTransfer>,
    pub data_hash: Option<&'a [u8; 32]>,
    pub ring_data_hash: Option<&'a [u8; 32]>,
    /// No output carries data, packed ciphertexts and exit payloads take their data-free lengths.
    pub data_free: bool,
    /// The policy proof escrows every output nullifier key, the ring mode's.
    pub key_escrow: bool,
    /// The anonymous entry key, every spent UTXO opens in full.
    pub full_openings: bool,
    /// Published order.
    pub outputs: Vec<RingOutput<'a>>,
    pub eph_u: &'a [u8; 32],
    pub sealed: &'a [u8; AUDIT_CIPHERTEXT_LEN],
    /// Exactly the fields the disclosure layout publishes.
    pub disclosure: &'a [[u8; 32]],
    pub private_tx_hash: &'a [u8; 32],
    /// Present exactly on the anonymous rail.
    pub anonymous: Option<AnonymousProofData<'a>>,
    pub spp_proof: &'a PlainGroth16Proof,
    /// One per spent input slot SPP publishes.
    pub nullifiers: &'a [[u8; 32]],
    pub input_trees: InputTrees,
}

impl<'a> RingTransactData<'a> {
    /// Every length fixed by the flags, the shape and the counts, trailing bytes refused.
    pub fn parse(data: &'a [u8], rail: RingRail) -> Result<ParsedTransact<'a>, CustomRingError> {
        let mut bytes = Bytes::new(data, CustomRingError::RingTransactLength);
        let flags = TransactFlags(bytes.byte()?);
        flags.check(rail)?;
        let header = FrameHeader::read(&mut bytes, rail)?;
        let input_count = header.input_count;
        let shape = rail.audit_shape(&header)?;
        let audit_proof = bytes.pod()?;
        let policy = match flags.has(transact_flag::POLICY) {
            false => None,
            true => Some(PolicyProof {
                proof: bytes.pod()?,
                own_root_index: bytes.byte()?,
                curator_root_index: flags
                    .has(transact_flag::CURATOR)
                    .then(|| bytes.byte())
                    .transpose()?,
                sender_commitment: (rail == RingRail::Anonymous)
                    .then(|| bytes.array())
                    .transpose()?,
            }),
        };
        let anchor = match flags.has(transact_flag::ANCHOR) {
            false => None,
            true => Some(AnchorRoot {
                tree: bytes.byte()?,
                root_index: bytes.u16()?,
            }),
        };
        let expiry_unix_ts = bytes.u32()?;
        let tx_viewing_u = bytes.array()?;
        let salt = bytes.array()?;
        let interface_transfers = bytes.interface_transfers()?;
        let data_hash = flags
            .has(transact_flag::DATA_HASH)
            .then(|| bytes.array())
            .transpose()?;
        let ring_data_hash = flags
            .has(transact_flag::RING_DATA_HASH)
            .then(|| bytes.array())
            .transpose()?;
        let output_count = match shape.fixed_outputs() {
            Some(outputs) => outputs,
            None => usize::from(bytes.byte()?),
        };
        let exits = bytes.bitmap(output_count)?;
        if rail == RingRail::Delegate && exits != 0 {
            return Err(CustomRingError::FlagNotAllowed);
        }
        let layout = shape.layout(output_count, header.flags.audit_layout(exits != 0))?;
        let frame = SlotFrame {
            layout,
            data_free: header.flags.data_free,
        };
        let outputs = (0..output_count)
            .map(|slot| match (exits >> slot) & 1 {
                1 => frame.read_exit(&mut bytes),
                _ => frame.read_ring(&mut bytes),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let eph_u = bytes.array()?;
        let sealed = bytes.array()?;
        let disclosure = bytes.fields(layout.field_count())?;
        let private_tx_hash = bytes.array()?;
        let anonymous = match rail {
            RingRail::Anonymous => Some(AnonymousProofData {
                commitment: bytes.array()?,
                commitment_pok: bytes.array()?,
                default_owner_tag: header
                    .flags
                    .default_owner_tag
                    .then(|| bytes.array())
                    .transpose()?,
            }),
            RingRail::Confidential | RingRail::Delegate => None,
        };
        let spp_proof = bytes.pod()?;
        let nullifiers = bytes.fields(usize::from(input_count))?;
        let input_trees = match flags.has(transact_flag::SECOND_TREE) {
            false => InputTrees::One(bytes.tree_context()?),
            true => {
                let second_inputs = bytes.bitmap(usize::from(input_count))?;
                InputTrees::Two {
                    first: bytes.tree_context()?,
                    second: bytes.tree_context()?,
                    second_inputs,
                }
            }
        };
        bytes.finish()?;
        let data = Self {
            rail,
            n_in: header.n_in,
            n_out: header.n_out,
            audit_proof,
            policy,
            approval_required: flags.has(transact_flag::APPROVAL_REQUIRED),
            previous_epoch: flags.has(transact_flag::PREVIOUS_EPOCH),
            anchor,
            expiry_unix_ts,
            tx_viewing_u,
            salt,
            interface_transfers,
            data_hash,
            ring_data_hash,
            data_free: header.flags.data_free,
            key_escrow: header.flags.key_escrow,
            full_openings: header.flags.full_openings,
            outputs,
            eph_u,
            sealed,
            disclosure,
            private_tx_hash,
            anonymous,
            spp_proof,
            nullifiers,
            input_trees,
        };
        Ok(ParsedTransact { data, layout })
    }

    /// The bytes `parse` reads back, refusing what it refuses.
    pub fn encode(&self) -> Result<Vec<u8>, CustomRingError> {
        let flags = self.flags();
        flags.check(self.rail)?;
        let header = FrameHeader::of(self)?;
        let output_count = self.outputs.len();
        let shape = self.rail.audit_shape(&header)?;
        let layout = shape.layout(output_count, self.audit_layout())?;
        let anonymous_rail = self.rail == RingRail::Anonymous;
        let commitment_fits = self
            .policy
            .is_none_or(|policy| policy.sender_commitment.is_some() == anonymous_rail);
        if !commitment_fits
            || self.anonymous.is_some() != anonymous_rail
            || self.disclosure.len() != layout.field_count()
            || !self.outputs.iter().all(|output| output.fits(layout))
        {
            return Err(CustomRingError::RingTransactLength);
        }
        if self.rail == RingRail::Delegate && self.outputs.iter().any(RingOutput::is_exit) {
            return Err(CustomRingError::FlagNotAllowed);
        }
        let mut out = vec![flags.0];
        out.extend(header.bytes()?);
        out.extend_from_slice(bytemuck::bytes_of(self.audit_proof));
        if let Some(policy) = &self.policy {
            out.extend_from_slice(bytemuck::bytes_of(policy.proof));
            out.push(policy.own_root_index);
            if let Some(index) = policy.curator_root_index {
                out.push(index);
            }
            if let Some(commitment) = policy.sender_commitment {
                out.extend_from_slice(commitment);
            }
        }
        if let Some(anchor) = self.anchor {
            out.push(anchor.tree);
            out.extend_from_slice(&anchor.root_index.to_le_bytes());
        }
        out.extend_from_slice(&self.expiry_unix_ts.to_le_bytes());
        out.extend_from_slice(self.tx_viewing_u);
        out.extend_from_slice(self.salt);
        out.extend(
            <containers::Vec<InterfaceTransfer, FixIntLen<u8>> as Serialize>::serialize(
                &self.interface_transfers,
            )
            .map_err(|_| CustomRingError::InvalidInstructionData)?,
        );
        for hash in [self.data_hash, self.ring_data_hash].into_iter().flatten() {
            out.extend_from_slice(hash);
        }
        if shape.fixed_outputs().is_none() {
            out.push(output_count as u8);
        }
        push_bitmap(&mut out, self.outputs.iter().map(RingOutput::is_exit));
        let frame = SlotFrame {
            layout,
            data_free: self.data_free,
        };
        for output in &self.outputs {
            frame.write(output, &mut out)?;
        }
        out.extend_from_slice(self.eph_u);
        out.extend_from_slice(self.sealed);
        out.extend_from_slice(self.disclosure.as_flattened());
        out.extend_from_slice(self.private_tx_hash);
        if let Some(anonymous) = &self.anonymous {
            out.extend_from_slice(anonymous.commitment);
            out.extend_from_slice(anonymous.commitment_pok);
            if let Some(tag) = anonymous.default_owner_tag {
                out.extend_from_slice(tag);
            }
        }
        out.extend_from_slice(bytemuck::bytes_of(self.spp_proof));
        out.extend_from_slice(self.nullifiers.as_flattened());
        match self.input_trees {
            InputTrees::One(context) => push_tree_context(&mut out, context)?,
            InputTrees::Two {
                first,
                second,
                second_inputs,
            } => {
                if second_inputs >> self.nullifiers.len() != 0 {
                    return Err(CustomRingError::InvalidInstructionData);
                }
                push_bitmap(
                    &mut out,
                    (0..self.nullifiers.len()).map(|input| (second_inputs >> input) & 1 == 1),
                );
                push_tree_context(&mut out, first)?;
                push_tree_context(&mut out, second)?;
            }
        }
        Ok(out)
    }

    /// The policy proof the registry of a policy ring demands, `None` on an audit-only ring.
    pub fn check_policy(
        &self,
        registry: Option<&MemberRegistry>,
    ) -> Result<Option<PolicyBinding<'a>>, CustomRingError> {
        let (proof, registry) = match (self.policy, registry) {
            (None, None) => return Ok(None),
            (Some(_), None) => return Err(CustomRingError::UnexpectedPolicyProof),
            (None, Some(_)) => return Err(CustomRingError::MissingPolicyProof),
            (Some(proof), Some(registry)) => (proof, registry),
        };
        let curator = match (proof.curator_root_index, registry.curator()) {
            (None, None) => None,
            (Some(root_index), Some(registry)) => Some(CuratorRoot {
                registry,
                root_index,
            }),
            _ => return Err(CustomRingError::FlagNotAllowed),
        };
        let limited = self.rail != RingRail::Delegate && registry.rules.has_limits();
        if self.approval_required && !limited {
            return Err(CustomRingError::UnexpectedApproval);
        }
        Ok(Some(PolicyBinding {
            proof,
            policy_hash: *registry.policy_hash()?,
            own_root: registry.own_root(proof.own_root_index)?,
            curator,
        }))
    }

    /// The SPP selector of the data's shape and rail.
    pub fn circuit(&self) -> CircuitId {
        let proof_data =
            self.anonymous
                .map_or(NO_PROOF_DATA, |anonymous| AnonymousRingEddsaProofData {
                    bsb22_commitment: Bsb22Commitment {
                        commitment: *anonymous.commitment,
                        commitment_pok: *anonymous.commitment_pok,
                    },
                    default_owner_tag: anonymous.default_owner_tag.copied(),
                });
        self.rail.circuit(self.n_in, self.n_out, proof_data)
    }

    pub fn first_nullifier(&self) -> Result<&'a [u8; 32], CustomRingError> {
        self.nullifiers
            .first()
            .ok_or(CustomRingError::RingTransactLength)
    }

    /// The statement epoch of a transfer landing at `slot`.
    pub fn epoch(&self, slot: u64) -> Result<u64, CustomRingError> {
        tag_epoch(slot)
            .checked_sub(u64::from(self.previous_epoch))
            .ok_or(CustomRingError::EpochUnderflow)
    }

    /// The anonymous policy statement's sender, zero on the other rails.
    pub fn sender_commitment(&self) -> &'a [u8; 32] {
        self.policy
            .and_then(|policy| policy.sender_commitment)
            .unwrap_or(&ZERO_FIELD)
    }

    /// The statement's layout element, the exits flag read from the outputs.
    pub fn audit_layout(&self) -> AuditLayout {
        FrameFlags::of(self).audit_layout(self.outputs.iter().any(RingOutput::is_exit))
    }

    pub fn disclosure_layout(&self) -> Result<DisclosureLayout, CustomRingError> {
        self.rail
            .audit_shape(&FrameHeader::of(self)?)?
            .layout(self.outputs.len(), self.audit_layout())
    }

    /// The SPP data the program forwards, `b` decompressed for SPP's verifier.
    pub fn expand(&self, config: &RingProgramConfig) -> Result<TransactIxData, CustomRingError> {
        let b = groth16_solana::decompression::decompress_g2(&self.spp_proof.proof_b)
            .map_err(|_| CustomRingError::InvalidSppProofPoint)?;
        self.transact_ix_data(
            config,
            TransactProof {
                a: self.spp_proof.proof_a,
                b,
                c: self.spp_proof.proof_c,
            },
        )
    }

    /// `tag || TransactIxData`, on the anonymous rail followed by the configured co-signer.
    pub fn spp_instruction_data(
        &self,
        config: &RingProgramConfig,
    ) -> Result<Vec<u8>, CustomRingError> {
        let expanded = self
            .expand(config)?
            .serialize()
            .map_err(|_| CustomRingError::InvalidInstructionData)?;
        let co_signer = match self.rail {
            RingRail::Anonymous => config.co_signer.as_array().as_slice(),
            RingRail::Confidential | RingRail::Delegate => &[],
        };
        Ok([&[self.rail.spp_tag()][..], &expanded, co_signer].concat())
    }

    /// The external data hash the SPP proof binds, computable before either proof exists.
    pub fn external_data_hash(
        &self,
        config: &RingProgramConfig,
        settlements: &[Settlement<'_>],
    ) -> Result<[u8; 32], CustomRingError> {
        let expanded = self
            .transact_ix_data(config, TransactProof::zeroed())?
            .serialize()
            .map_err(|_| CustomRingError::InvalidInstructionData)?;
        let parsed = TransactIxDataRef::parse_with_tail(&expanded)
            .map_err(|_| CustomRingError::InvalidInstructionData)?;
        let tag = [self.rail.spp_tag()];
        let mut preimage = ExternalDataPreimage::new(&tag, parsed.external_data_prefix);
        for settlement in settlements {
            preimage.push_settlement(settlement.asset_account, settlement.user_account)?;
        }
        Ok(preimage.finish()?)
    }

    /// The expansion under `proof`, a client sizes the transaction with a zeroed one.
    pub fn transact_ix_data(
        &self,
        config: &RingProgramConfig,
        proof: TransactProof,
    ) -> Result<TransactIxData, CustomRingError> {
        let view_tag: [u8; 32] = core::array::from_fn(|i| config.auditor_pubkey[i + 1]);
        Ok(TransactIxData {
            expiry_unix_ts: u64::from(self.expiry_unix_ts),
            tx_viewing_pk: tagged_x25519(self.tx_viewing_u),
            salt: *self.salt,
            interface_transfers: self.interface_transfers.clone(),
            data_hash: self.data_hash.copied(),
            ring_data_hash: self.ring_data_hash.copied(),
            outputs: self
                .outputs
                .iter()
                .map(RingOutput::transact_output)
                .collect(),
            messages: vec![MessageData {
                view_tag,
                data: AuditorMessage::data(self.eph_u, self.sealed, self.disclosure),
            }],
            private_tx_hash: *self.private_tx_hash,
            circuit: self.circuit(),
            proof,
            inputs: self
                .nullifiers
                .iter()
                .enumerate()
                .map(|(input, nullifier)| InputUtxo {
                    nullifier_hash: *nullifier,
                    tree_index: self.input_trees.tree_index(input),
                })
                .collect(),
            tree_contexts: self.input_trees.contexts(),
        })
    }

    fn flags(&self) -> TransactFlags {
        let bits = [
            (self.policy.is_some(), transact_flag::POLICY),
            (
                self.policy
                    .is_some_and(|policy| policy.curator_root_index.is_some()),
                transact_flag::CURATOR,
            ),
            (self.approval_required, transact_flag::APPROVAL_REQUIRED),
            (self.previous_epoch, transact_flag::PREVIOUS_EPOCH),
            (self.anchor.is_some(), transact_flag::ANCHOR),
            (
                matches!(self.input_trees, InputTrees::Two { .. }),
                transact_flag::SECOND_TREE,
            ),
            (self.data_hash.is_some(), transact_flag::DATA_HASH),
            (self.ring_data_hash.is_some(), transact_flag::RING_DATA_HASH),
        ];
        TransactFlags(
            bits.into_iter()
                .filter(|(set, _)| *set)
                .fold(0, |flags, (_, bit)| flags | bit),
        )
    }
}

/// Byte 0 of the compact data, one bit per optional section.
pub mod transact_flag {
    pub const BYTE: usize = 0;
    pub const POLICY: u8 = 1 << 0;
    pub const CURATOR: u8 = 1 << 1;
    pub const APPROVAL_REQUIRED: u8 = 1 << 2;
    pub const PREVIOUS_EPOCH: u8 = 1 << 3;
    pub const ANCHOR: u8 = 1 << 4;
    pub const SECOND_TREE: u8 = 1 << 5;
    pub const DATA_HASH: u8 = 1 << 6;
    pub const RING_DATA_HASH: u8 = 1 << 7;
}

/// Byte 1, the index into `SPP_SUPPORTED_SHAPES` below these flags.
pub mod shape_flag {
    pub const BYTE: usize = 1;
    pub const DEFAULT_OWNER_TAG: u8 = 1 << 6;
    pub const DATA_FREE: u8 = 1 << 7;
}

/// Byte 2, the published input count below these flags.
pub mod input_flag {
    pub const BYTE: usize = 2;
    pub const KEY_ESCROW: u8 = 1 << 6;
    pub const FULL_OPENINGS: u8 = 1 << 7;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TransactFlags(u8);

impl TransactFlags {
    const fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    /// The curator and approval flags need a policy, the epoch and anchor flags an anonymous ring.
    fn check(self, rail: RingRail) -> Result<(), CustomRingError> {
        let needs_policy =
            self.has(transact_flag::CURATOR) || self.has(transact_flag::APPROVAL_REQUIRED);
        let needs_anonymous =
            self.has(transact_flag::PREVIOUS_EPOCH) || self.has(transact_flag::ANCHOR);
        if (needs_policy && !self.has(transact_flag::POLICY))
            || (needs_anonymous && rail != RingRail::Anonymous)
        {
            return Err(CustomRingError::FlagNotAllowed);
        }
        Ok(())
    }
}

/// Bytes 1 and 2 of the compact data, the SPP shape's index and the input count below their flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FrameHeader {
    n_in: u8,
    n_out: u8,
    input_count: u8,
    flags: FrameFlags,
}

impl FrameHeader {
    /// The shape index or the input count, bits 6 and 7 carry the flags.
    const LOW: u8 = 0b0011_1111;

    fn read(bytes: &mut Bytes<'_>, rail: RingRail) -> Result<Self, CustomRingError> {
        let [shape, inputs] = *bytes.array()?;
        let spp_shape = SPP_SUPPORTED_SHAPES
            .get(usize::from(shape & Self::LOW))
            .ok_or(CustomRingError::RingShapeUnkeyed)?;
        let flags = FrameFlags {
            default_owner_tag: shape & shape_flag::DEFAULT_OWNER_TAG != 0,
            data_free: shape & shape_flag::DATA_FREE != 0,
            key_escrow: inputs & input_flag::KEY_ESCROW != 0,
            full_openings: inputs & input_flag::FULL_OPENINGS != 0,
        };
        flags.check(rail)?;
        Ok(Self {
            n_in: count_byte(spp_shape.n_inputs())?,
            n_out: count_byte(spp_shape.n_outputs())?,
            input_count: inputs & Self::LOW,
            flags,
        })
    }

    fn of(data: &RingTransactData<'_>) -> Result<Self, CustomRingError> {
        let flags = FrameFlags::of(data);
        flags.check(data.rail)?;
        Ok(Self {
            n_in: data.n_in,
            n_out: data.n_out,
            input_count: count_byte(data.nullifiers.len())?,
            flags,
        })
    }

    fn bytes(self) -> Result<[u8; 2], CustomRingError> {
        let shape = Shape::new(usize::from(self.n_in), usize::from(self.n_out));
        let index = SPP_SUPPORTED_SHAPES
            .iter()
            .position(|supported| *supported == shape)
            .ok_or(CustomRingError::RingShapeUnkeyed)?;
        if self.input_count > Self::LOW {
            return Err(CustomRingError::RingTransactLength);
        }
        let flag = |set: bool, bit: u8| if set { bit } else { 0 };
        let flags = self.flags;
        Ok([
            index as u8
                | flag(flags.default_owner_tag, shape_flag::DEFAULT_OWNER_TAG)
                | flag(flags.data_free, shape_flag::DATA_FREE),
            self.input_count
                | flag(flags.key_escrow, input_flag::KEY_ESCROW)
                | flag(flags.full_openings, input_flag::FULL_OPENINGS),
        ])
    }
}

const _: () = assert!(
    SPP_SUPPORTED_SHAPES.len() <= FrameHeader::LOW as usize + 1
        && zolana_interface::MAX_TRANSACT_INPUTS <= FrameHeader::LOW as usize
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FrameFlags {
    /// Shape byte bit 6, the anonymous rail's default owner tag follows the commitment pok.
    default_owner_tag: bool,
    /// Shape byte bit 7.
    data_free: bool,
    /// Input byte bit 6.
    key_escrow: bool,
    /// Input byte bit 7, the anonymous entry key.
    full_openings: bool,
}

impl FrameFlags {
    fn of(data: &RingTransactData<'_>) -> Self {
        Self {
            default_owner_tag: data
                .anonymous
                .is_some_and(|anonymous| anonymous.default_owner_tag.is_some()),
            data_free: data.data_free,
            key_escrow: data.key_escrow,
            full_openings: data.full_openings,
        }
    }

    /// The anonymous rail alone takes a default owner tag and the entry key, the audit binding
    /// holds the key escrow flag to the ring mode.
    fn check(self, rail: RingRail) -> Result<(), CustomRingError> {
        match rail != RingRail::Anonymous && (self.default_owner_tag || self.full_openings) {
            true => Err(CustomRingError::FlagNotAllowed),
            false => Ok(()),
        }
    }

    fn audit_layout(self, exits: bool) -> AuditLayout {
        AuditLayout {
            exits,
            key_escrow: self.key_escrow,
            data_free: self.data_free,
            full_openings: self.full_openings,
        }
    }
}

fn count_byte(count: usize) -> Result<u8, CustomRingError> {
    u8::try_from(count).map_err(|_| CustomRingError::RingTransactLength)
}

fn push_sized(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CustomRingError> {
    let len = u16::try_from(bytes.len()).map_err(|_| CustomRingError::RingTransactLength)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn push_bitmap(out: &mut Vec<u8>, bits: impl ExactSizeIterator<Item = bool>) {
    let mut bytes = vec![0u8; bits.len().div_ceil(8)];
    for (index, _) in bits.enumerate().filter(|(_, set)| *set) {
        bytes[index / 8] |= 1 << (index % 8);
    }
    out.extend_from_slice(&bytes);
}

fn push_tree_context(out: &mut Vec<u8>, context: TreeContext) -> Result<(), CustomRingError> {
    out.extend(
        <TreeContext as Serialize>::serialize(&context)
            .map_err(|_| CustomRingError::InvalidInstructionData)?,
    );
    Ok(())
}
