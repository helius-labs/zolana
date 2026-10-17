//! Prover bodies. Field names are the wire names the Go prover decodes, the golden
//! files pin them, and `registry` is the one place the record openings are spelled.

use custom_ring_interface::{
    MemberUpdate, AUDIT_INPUT_SLOTS, MAX_MEMBER_BATCH, MAX_RING_DEPOSIT_AUDIT_SLOTS,
    TAGGED_X25519_KEY_LEN,
};
use serde::{ser::SerializeStruct, Serialize, Serializer};
use zeroize::Zeroizing;
use zolana_client::ProofInputUtxo;
use zolana_keypair::{ViewingKey, X25519Pubkey};
use zolana_ring_policy::{OutflowLimit, PolicySource, MAX_OUTFLOW_LIMITS, POLICY_OUTPUT_SLOTS};

pub(crate) use registry::{RecordUpdate, RecordWitness, SubjectWitness};

use crate::{
    prover::{
        fe::{self, Hex},
        RingBody, RingCircuit,
    },
    witness::{CustomRingWitness, PolicyTree},
    CustomRing, RingError,
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
}

/// An output slot with the hash of its owner's sealed key ciphertext, zero without escrow.
#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CustomRingOutputOpening {
    #[serde(flatten)]
    pub opening: CustomRingOpening,
    #[serde(with = "fe")]
    pub ct_hash: [u8; 32],
}

/// The member registry witnesses, one spelling for every circuit that opens a record.
pub(crate) mod registry {
    use custom_ring_interface::{MemberRecord, MemberUpdate, MEMBER_REGISTRY_HEIGHT};
    use serde::Serialize;

    use crate::{member_registry::RecordOpening, prover::fe};

    /// A record under a root, the `RecordOpening` wires of the deposit circuit.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct RecordWitness {
        #[serde(with = "fe")]
        pub next: [u8; 32],
        pub lists: u64,
        #[serde(with = "fe")]
        pub escrow_key: [u8; 32],
        pub index: u64,
        #[serde(serialize_with = "fe::seq")]
        pub path: Vec<[u8; 32]>,
    }

    /// A member present, or absent under its low record, the `MemberOpening` wires.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct SubjectWitness {
        pub present: bool,
        #[serde(flatten)]
        pub record: RecordWitness,
        #[serde(with = "fe")]
        pub low_member: [u8; 32],
        #[serde(with = "fe")]
        pub low_next: [u8; 32],
        pub low_lists: u64,
        #[serde(with = "fe")]
        pub low_escrow: [u8; 32],
    }

    /// One record rewrite or insert, the `RecordUpdate` wires. An insert relinks the low
    /// record and opens the empty leaf at `index` after the relink.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct RecordUpdate {
        pub exists: bool,
        #[serde(with = "fe")]
        pub next: [u8; 32],
        pub index: u64,
        #[serde(serialize_with = "fe::seq")]
        pub path: Vec<[u8; 32]>,
        #[serde(with = "fe")]
        pub low_member: [u8; 32],
        #[serde(with = "fe")]
        pub low_next: [u8; 32],
        pub low_lists: u64,
        #[serde(with = "fe")]
        pub low_escrow: [u8; 32],
        pub low_index: u64,
        #[serde(serialize_with = "fe::seq")]
        pub low_path: Vec<[u8; 32]>,
    }

    /// One batch item, the program's `MemberUpdate` with its tree witness.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct MemberUpdateWitness {
        #[serde(with = "fe")]
        pub member: [u8; 32],
        pub old_lists: u64,
        #[serde(with = "fe")]
        pub old_escrow_key: [u8; 32],
        pub lists: u64,
        #[serde(with = "fe")]
        pub escrow_key: [u8; 32],
        #[serde(flatten)]
        pub update: RecordUpdate,
    }

    impl MemberUpdateWitness {
        pub fn new(item: &MemberUpdate, update: RecordUpdate) -> Self {
            Self {
                member: item.member,
                old_lists: item.old_lists,
                old_escrow_key: item.old_escrow_key,
                lists: item.lists,
                escrow_key: item.escrow_key,
                update,
            }
        }
    }

    impl RecordWitness {
        pub fn present(record: &MemberRecord, index: u64, path: Vec<[u8; 32]>) -> Self {
            Self {
                next: record.next,
                lists: record.lists,
                escrow_key: record.escrow_key,
                index,
                path,
            }
        }
    }

    impl SubjectWitness {
        /// The circuit opens the record itself when present, the low record when absent.
        pub fn of(opening: &RecordOpening) -> Self {
            match opening {
                RecordOpening::Present {
                    record,
                    index,
                    path,
                    ..
                } => Self {
                    present: true,
                    record: RecordWitness::present(record, *index, path.clone()),
                    low_member: [0; 32],
                    low_next: [0; 32],
                    low_lists: 0,
                    low_escrow: [0; 32],
                },
                RecordOpening::Absent {
                    low,
                    low_index,
                    path,
                } => Self {
                    present: false,
                    record: RecordWitness {
                        next: [0; 32],
                        lists: 0,
                        escrow_key: [0; 32],
                        index: *low_index,
                        path: path.clone(),
                    },
                    low_member: low.member,
                    low_next: low.next,
                    low_lists: low.lists,
                    low_escrow: low.escrow_key,
                },
            }
        }
    }

    impl RecordUpdate {
        pub fn rewrite(next: [u8; 32], index: u64, path: Vec<[u8; 32]>) -> Self {
            Self {
                exists: true,
                next,
                index,
                path,
                low_member: [0; 32],
                low_next: [0; 32],
                low_lists: 0,
                low_escrow: [0; 32],
                low_index: 0,
                low_path: vec![[0; 32]; MEMBER_REGISTRY_HEIGHT],
            }
        }

        pub fn insert(
            low: &MemberRecord,
            low_index: u64,
            low_path: Vec<[u8; 32]>,
            index: u64,
            path: Vec<[u8; 32]>,
        ) -> Self {
            Self {
                exists: false,
                next: low.next,
                index,
                path,
                low_member: low.member,
                low_next: low.next,
                low_lists: low.lists,
                low_escrow: low.escrow_key,
                low_index,
                low_path,
            }
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
    pub recipients: Vec<[u8; IDENTITY_LEN]>,
    #[serde(serialize_with = "fe::seq")]
    pub recipient_viewing_keys: Vec<[u8; TAGGED_X25519_KEY_LEN]>,
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
    /// Zero without escrow and in padding.
    #[serde(serialize_with = "fe::seq")]
    pub ct_hashes: [[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    /// `None` without escrow and in padding.
    pub members: [Option<RecordWitness>; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    #[serde(rename = "ephSk", serialize_with = "fe::zeroizing")]
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "fe::coordinate")]
    pub auditor_pk: X25519Pubkey,
    pub key_escrow: bool,
    #[serde(with = "fe")]
    pub member_registry_root: [u8; 32],
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
    /// The record's lists, kept as they are.
    pub lists: u64,
    #[serde(flatten)]
    pub update: RecordUpdate,
    /// The 31-byte secret right aligned, the zero high byte keeps it below the field order.
    #[serde(serialize_with = "fe::zeroizing")]
    pub nullifier_secret: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "fe::zeroizing")]
    pub eph_sk: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "fe::coordinate")]
    pub auditor_pk: X25519Pubkey,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpdateMembersBody {
    pub circuit_type: RingCircuit,
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(with = "fe")]
    pub old_root: [u8; 32],
    #[serde(with = "fe")]
    pub new_root: [u8; 32],
    pub item_count: u8,
    /// `None` past the count.
    pub items: Vec<Option<registry::MemberUpdateWitness>>,
}

impl UpdateMembersBody {
    pub fn new(
        public_input_hash: [u8; 32],
        old_root: [u8; 32],
        new_root: [u8; 32],
        items: &[MemberUpdate],
        updates: Vec<RecordUpdate>,
    ) -> Self {
        let mut witnesses: Vec<Option<registry::MemberUpdateWitness>> = items
            .iter()
            .zip(updates)
            .map(|(item, update)| Some(registry::MemberUpdateWitness::new(item, update)))
            .collect();
        witnesses.resize_with(MAX_MEMBER_BATCH, || None);
        Self {
            circuit_type: RingCircuit::UpdateMembers,
            public_input_hash,
            old_root,
            new_root,
            item_count: items.len() as u8,
            items: witnesses,
        }
    }
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
    RegisterKeyBody,
    UpdateMembersBody
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
    sources: &[PolicySource],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(sources.iter().map(Source))
}

struct Source<'a>(&'a PolicySource);

impl Serialize for Source<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Source", 2)?;
        state.serialize_field("listId", &self.0.list_id)?;
        state.serialize_field("registry", &Hex(self.0.registry))?;
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

/// Input owners, output owners and output assets. Unused slots send `null`.
pub(crate) fn subjects<S: Serializer>(
    subjects: &[Option<SubjectWitness>],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(subjects.iter())
}

fn int(value: u64) -> [u8; 32] {
    zolana_hasher::primitives::right_align(&value.to_be_bytes())
}
