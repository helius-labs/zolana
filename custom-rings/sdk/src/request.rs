//! Prover bodies. Field order is the wire order the golden files pin.

use custom_ring_interface::{
    AUDIT_INPUT_SLOTS, MAX_RING_DEPOSIT_AUDIT_SLOTS, TAGGED_X25519_KEY_LEN,
};
use serde::{ser::SerializeStruct, Serialize, Serializer};
use zeroize::Zeroizing;
use zolana_client::ProofInputUtxo;
use zolana_keypair::{ViewingKey, X25519Pubkey};
use zolana_ring_policy::{OutflowLimit, SourceOwner, MAX_OUTFLOW_LIMITS, POLICY_OUTPUT_SLOTS};

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
    /// `None` with escrow off or in padding.
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

/// The pinned outflow limits and the approval demand the transfer proves under them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutflowLimitProofInput {
    #[serde(serialize_with = "outflow_limits")]
    pub limits: [OutflowLimit; MAX_OUTFLOW_LIMITS],
    pub limit_count: u8,
    #[serde(with = "fe")]
    pub ring_id: [u8; 32],
    #[serde(with = "fe")]
    pub namespace_owner_hash: [u8; 32],
    pub approval_required: bool,
}

impl OutflowLimitProofInput {
    /// A ring without limits still binds its id and namespace.
    pub fn none(identity: RingIdentity) -> Self {
        Self {
            limits: [OutflowLimit::EMPTY; MAX_OUTFLOW_LIMITS],
            limit_count: 0,
            ring_id: identity.ring_id,
            namespace_owner_hash: identity.namespace_owner_hash,
            approval_required: false,
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

/// An owner tag byte followed by the 32 key bytes.
pub(crate) const IDENTITY_LEN: usize = 33;

/// The hidden parties an anonymous statement binds, absent from the wire otherwise.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AnonymousIdentities {
    #[serde(rename = "anonymous")]
    pub flag: AnonymousFlag,
    #[serde(with = "fe")]
    pub sender: [u8; IDENTITY_LEN],
    #[serde(serialize_with = "fe::seq")]
    pub recipients: [[u8; IDENTITY_LEN]; POLICY_OUTPUT_SLOTS],
    #[serde(serialize_with = "fe::seq")]
    pub recipient_viewing_keys: [[u8; TAGGED_X25519_KEY_LEN]; POLICY_OUTPUT_SLOTS],
}

/// The base circuit opens the SPP slots itself, the policy witness opens them otherwise.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AnonymousBase {
    #[serde(flatten)]
    pub identities: AnonymousIdentities,
    pub n_in: u8,
    pub inputs: [CustomRingOpening; AUDIT_INPUT_SLOTS],
    pub anonymous_outputs: [CustomRingOpening; POLICY_OUTPUT_SLOTS],
    #[serde(with = "fe")]
    pub private_tx_blinding: [u8; 32],
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
    #[serde(flatten)]
    pub anonymous: Option<AnonymousBase>,
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
    pub anonymous: Option<AnonymousIdentities>,
    #[serde(flatten)]
    pub witness: Box<CustomRingWitness>,
}

/// The delegate circuit reads the policy body under `policy`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PolicyEnvelope<'a> {
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
    #[serde(skip_serializing_if = "core::ops::Not::not")]
    pub anonymous: bool,
    #[serde(serialize_with = "fe::seq")]
    pub owner_pk_hashes: [[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    /// The Ed25519 owner keys an anonymous ring discloses, absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "owner_keys")]
    pub owner_keys: Option<[[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS]>,
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

/// Always `true`, the anonymous fields travel only with their mode.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AnonymousFlag;

impl Serialize for AnonymousFlag {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bool(true)
    }
}

fn owner_keys<S: Serializer>(
    keys: &Option<[[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS]>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match keys {
        Some(keys) => fe::seq(keys, serializer),
        None => serializer.serialize_none(),
    }
}

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

pub(crate) fn outflow_limits<S: Serializer>(
    limits: &[OutflowLimit],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(limits.iter().map(Limit))
}

struct Limit<'a>(&'a OutflowLimit);

impl Serialize for Limit<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let limit = self.0;
        fields(
            serializer,
            [
                ("asset", &limit.asset),
                ("cap", &int(limit.cap)),
                ("cosignAbove", &int(limit.cosign_above)),
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

fn int(value: u64) -> [u8; 32] {
    zolana_hasher::primitives::right_align(&value.to_be_bytes())
}
