//! Prover bodies. Field order is the wire order the golden files pin.

use custom_ring_interface::MAX_RING_DEPOSIT_AUDIT_SLOTS;
use serde::{ser::SerializeStruct, Serialize, Serializer};
use zeroize::Zeroizing;
use zolana_client::ProofInputUtxo;
use zolana_keypair::{ViewingKey, X25519Pubkey};
use zolana_ring_policy::{SourceOwner, VelocityRow, MAX_VELOCITY_ASSETS, POLICY_OUTPUT_SLOTS};

use crate::{
    escrow::RegistryKeyOpening,
    prover::{
        fe::{self, Hex},
        RingBody, RingCircuit,
    },
    witness::{CustomRingWitness, PolicyTree},
    CurrentKeyRegistryRoot, CustomRing, RingError,
};

/// One opened UTXO slot, in the order the circuit hashes it.
#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CustomRingOpening {
    #[serde(with = "fe")]
    pub domain: [u8; 32],
    #[serde(with = "fe")]
    pub tree_id: [u8; 32],
    #[serde(with = "fe")]
    pub owner_pk_hash: [u8; 32],
    #[serde(with = "fe")]
    pub nullifier_pk: [u8; 32],
    #[serde(with = "fe")]
    pub asset: [u8; 32],
    #[serde(with = "fe")]
    pub amount: [u8; 32],
    #[serde(with = "fe")]
    pub blinding: [u8; 32],
    #[serde(with = "fe")]
    pub data_hash: [u8; 32],
    #[serde(with = "fe")]
    pub ring_data_hash: [u8; 32],
    #[serde(with = "fe")]
    pub ring_program_id: [u8; 32],
    /// `None` with escrow off, in padding, or on a namespace-owned record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<RegistryKeyOpening>,
}

/// One entry fact, proven against the roots of its tree slot.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RuleAnswer {
    pub enabled: bool,
    /// Index into the statement's policy trees.
    pub tree_slot: u8,
    pub mode: u8,
    pub list_id: u8,
    pub state: u8,
    pub absent_branch: u8,
    #[serde(with = "fe")]
    pub member: [u8; 32],
    #[serde(with = "fe")]
    pub content_hash: [u8; 32],
    pub version: u64,
    #[serde(with = "fe")]
    pub blinding: [u8; 32],
    #[serde(with = "fe")]
    pub low: [u8; 32],
    #[serde(with = "fe")]
    pub next: [u8; 32],
    #[serde(rename = "nfPathElements", serialize_with = "fe::seq")]
    pub nullifier_path: Vec<[u8; 32]>,
    #[serde(rename = "nfPathIndex")]
    pub nullifier_path_index: u64,
    #[serde(rename = "statePathElements", serialize_with = "fe::seq")]
    pub state_path: Vec<[u8; 32]>,
    pub state_path_index: u64,
}

impl Default for RuleAnswer {
    /// The circuit's disabled slot, its branch flags and list stay in range.
    fn default() -> Self {
        Self {
            enabled: false,
            tree_slot: 0,
            mode: 1,
            list_id: 1,
            state: 1,
            absent_branch: 1,
            member: [0; 32],
            content_hash: [0; 32],
            version: 0,
            blinding: [0; 32],
            low: [0; 32],
            next: [0; 32],
            nullifier_path: vec![[0; 32]; zolana_client::NULLIFIER_TREE_HEIGHT],
            nullifier_path_index: 0,
            state_path: vec![[0; 32]; zolana_client::STATE_TREE_HEIGHT],
            state_path_index: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpendRecordProofInput {
    pub version: u64,
    pub window: u64,
    #[serde(with = "fe")]
    pub commitment: [u8; 32],
    #[serde(with = "fe")]
    pub salt: [u8; 32],
    #[serde(serialize_with = "fe::seq")]
    pub assets: [[u8; 32]; MAX_VELOCITY_ASSETS],
    #[serde(serialize_with = "fe::ints")]
    pub spent: [u64; MAX_VELOCITY_ASSETS],
    #[serde(with = "fe")]
    pub next_salt: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingIdentity {
    pub ring_id: [u8; 32],
    pub namespace_owner_hash: [u8; 32],
}

impl RingIdentity {
    pub(crate) fn new(ring: CustomRing, namespace_owner_hash: [u8; 32]) -> Result<Self, RingError> {
        Ok(Self {
            ring_id: zolana_ring_policy::ring_id_field(ring.program_id().as_array())?,
            namespace_owner_hash,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VelocityProofInput {
    pub window_slots: u64,
    #[serde(rename = "velocity", serialize_with = "velocity_rows")]
    pub rows: [VelocityRow; MAX_VELOCITY_ASSETS],
    #[serde(rename = "velocityCount")]
    pub row_count: u8,
    #[serde(with = "fe")]
    pub ring_id: [u8; 32],
    #[serde(with = "fe")]
    pub namespace_owner_hash: [u8; 32],
    pub window_index: u64,
    pub approval_required: bool,
    pub record: SpendRecordProofInput,
}

impl VelocityProofInput {
    /// A ring without a window still binds its id and namespace.
    pub fn off(identity: RingIdentity) -> Self {
        Self {
            window_slots: 0,
            rows: [VelocityRow::EMPTY; MAX_VELOCITY_ASSETS],
            row_count: 0,
            ring_id: identity.ring_id,
            namespace_owner_hash: identity.namespace_owner_hash,
            window_index: 0,
            approval_required: false,
            record: SpendRecordProofInput::default(),
        }
    }
}

/// The audit witness every audited statement opens.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuditSecrets {
    #[serde(with = "fe")]
    pub private_tx_hash: [u8; 32],
    #[serde(rename = "txViewingSk", serialize_with = "fe::secret")]
    pub tx_viewing_key: ViewingKey,
    #[serde(rename = "ephSk", serialize_with = "fe::zeroizing")]
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
    #[serde(rename = "auditorPk", serialize_with = "fe::coordinate")]
    pub auditor_key: X25519Pubkey,
    #[serde(with = "fe")]
    pub salt: [u8; 16],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BaseBody {
    pub circuit_type: RingCircuit,
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(flatten)]
    pub audit: AuditSecrets,
    pub n_out: u8,
    #[serde(serialize_with = "audit_outputs")]
    pub outputs: Vec<ProofInputUtxo>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PolicyBody {
    pub circuit_type: RingCircuit,
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(flatten)]
    pub audit: AuditSecrets,
    #[serde(flatten)]
    pub witness: Box<CustomRingWitness>,
}

/// The delegate and compressed circuits read the policy body under `policy`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PolicyEnvelope<'a> {
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "optional_salt"
    )]
    pub transaction_salt: Option<[u8; 16]>,
    pub circuit_type: RingCircuit,
    pub policy: &'a PolicyBody,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DepositBody {
    pub circuit_type: RingCircuit,
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(with = "fe")]
    pub context_hash: [u8; 32],
    pub count: u8,
    #[serde(serialize_with = "fe::seq")]
    pub owner_pk_hashes: [[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    #[serde(serialize_with = "fe::seq")]
    pub nullifier_pks: [[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    #[serde(serialize_with = "fe::zeroizing_seq")]
    pub blindings: Zeroizing<[[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS]>,
    /// `None` with escrow off and in padding.
    pub keys: [Option<RegistryKeyOpening>; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    #[serde(rename = "ephSk", serialize_with = "fe::zeroizing")]
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "fe::coordinate")]
    pub auditor_pk: X25519Pubkey,
    pub key_escrow: bool,
    #[serde(with = "fe")]
    pub key_registry_root: [u8; 32],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegisterKeyBody {
    pub circuit_type: RingCircuit,
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(with = "fe")]
    pub registry_old_root: [u8; 32],
    #[serde(with = "fe")]
    pub registry_new_root: [u8; 32],
    #[serde(with = "fe")]
    pub member: [u8; 32],
    #[serde(serialize_with = "fe::int")]
    pub new_index: u64,
    /// The 31-byte secret right aligned, the zero high byte keeps it below the field order.
    #[serde(serialize_with = "fe::zeroizing")]
    pub nullifier_secret: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "fe::zeroizing")]
    pub eph_sk: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "fe::coordinate")]
    pub auditor_pk: X25519Pubkey,
    #[serde(with = "fe")]
    pub low_member: [u8; 32],
    #[serde(with = "fe")]
    pub low_next: [u8; 32],
    #[serde(with = "fe")]
    pub low_key: [u8; 32],
    #[serde(serialize_with = "fe::int")]
    pub low_index: u64,
    #[serde(serialize_with = "fe::seq")]
    pub low_proof: Vec<[u8; 32]>,
    #[serde(serialize_with = "fe::seq")]
    pub new_proof: Vec<[u8; 32]>,
}

macro_rules! ring_bodies {
    ($($body:ty),*) => {$(
        impl RingBody for $body {
            fn circuit(&self) -> RingCircuit {
                self.circuit_type
            }
        }
    )*};
}

ring_bodies!(
    BaseBody,
    PolicyBody,
    PolicyEnvelope<'_>,
    DepositBody,
    RegisterKeyBody
);

fn audit_outputs<S: Serializer>(
    outputs: &[ProofInputUtxo],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let zero = ProofInputUtxo::default();
    let slots: Vec<_> = (0..POLICY_OUTPUT_SLOTS)
        .map(|slot| outputs.get(slot).unwrap_or(&zero))
        .collect();
    serializer.collect_seq(slots.into_iter().map(AuditOpening))
}

struct AuditOpening<'a>(&'a ProofInputUtxo);

impl Serialize for AuditOpening<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let utxo = self.0;
        fields(
            serializer,
            [
                ("domain", &utxo.domain),
                ("treeId", &utxo.tree_id),
                ("ownerHash", &utxo.owner_hash),
                ("asset", &utxo.asset),
                ("amount", &utxo.amount),
                ("blinding", &utxo.blinding),
                ("dataHash", &utxo.data_hash),
                ("ringDataHash", &utxo.ring_data_hash),
                ("ringProgramId", &utxo.ring_program_id),
            ],
        )
    }
}

fn fields<S: Serializer, const N: usize>(
    serializer: S,
    fields: [(&'static str, &[u8; 32]); N],
) -> Result<S::Ok, S::Error> {
    let mut state = serializer.serialize_struct("Fields", N)?;
    for (name, value) in fields {
        state.serialize_field(name, &Hex(value))?;
    }
    state.end()
}

pub(crate) fn velocity_rows<S: Serializer>(
    rows: &[VelocityRow],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(rows.iter().map(Row))
}

struct Row<'a>(&'a VelocityRow);

impl Serialize for Row<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let row = self.0;
        fields(
            serializer,
            [
                ("asset", &row.asset),
                ("cap", &int(row.cap)),
                ("cosignAbove", &int(row.cosign_above)),
            ],
        )
    }
}

pub(crate) fn sources<S: Serializer>(
    sources: &[SourceOwner],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(sources.iter().map(Source))
}

struct Source<'a>(&'a SourceOwner);

impl Serialize for Source<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Source", 2)?;
        state.serialize_field("listId", &self.0.list_id)?;
        state.serialize_field("ownerHash", &Hex(self.0.owner_hash))?;
        state.end()
    }
}

pub(crate) fn tree_slots<S: Serializer>(
    trees: &[PolicyTree],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(trees.iter().map(Slot))
}

struct Slot<'a>(&'a PolicyTree);

impl Serialize for Slot<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let slot = self.0.slot();
        fields(
            serializer,
            [
                ("id", &slot.id),
                ("utxoRoot", &slot.utxo_root),
                ("nullifierRoot", &slot.nullifier_root),
            ],
        )
    }
}

/// `keyEscrow` and the root it binds, a zero root with escrow off.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Escrow(pub Option<CurrentKeyRegistryRoot>);

impl Serialize for Escrow {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Escrow", 2)?;
        state.serialize_field("keyEscrow", &self.0.is_some())?;
        state.serialize_field(
            "keyRegistryRoot",
            &Hex(self.0.map(|root| root.root).unwrap_or_default()),
        )?;
        state.end()
    }
}

fn optional_salt<S: Serializer>(salt: &Option<[u8; 16]>, serializer: S) -> Result<S::Ok, S::Error> {
    fe::bytes(&salt.unwrap_or_default(), serializer)
}

fn int(value: u64) -> [u8; 32] {
    zolana_hasher::primitives::right_align(&value.to_be_bytes())
}
