//! The ring prover's request bodies, field for field the Go `prover/custom_ring` params.

use custom_ring_interface::{
    QueueEntry, MAX_RING_DEPOSIT_AUDIT_SLOTS, QUAD_ARITY, RING_DELIVERED_BODY_LEN,
};
use serde::{Serialize, Serializer};
use zeroize::Zeroizing;
use zolana_keypair::{PublicKey, X25519Pubkey};
use zolana_ring_member_registry::{MemberRecord, QuadPath, RecordOpening, RecordWriteProofInput};
use zolana_ring_policy::{EncodedRuleTable, SourceMap, MAX_SOURCES};
use zolana_transaction::{
    instructions::transact::SppProofOutputUtxo,
    utxo::{ProofInputUtxo, SppProofInputUtxo},
};

use crate::{prover::fe, RingError};

#[cfg(test)]
#[path = "tests/request.rs"]
mod tests;

pub(crate) const REDACTED: &str = "<redacted>";

/// One transaction slot as SPP hashes it, its owner split into the identity and the nullifier key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Opening {
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

impl Opening {
    pub fn output(output: &SppProofOutputUtxo, tree_id: u16) -> Result<Self, RingError> {
        let owner = output.owner_address;
        Ok(Self::with_owner(
            ProofInputUtxo::try_from((output, tree_id))?,
            owner
                .map(|owner| owner.signing_pubkey.owner_proof_input_hash())
                .transpose()?
                .unwrap_or_default(),
            owner
                .map(|owner| owner.nullifier_pubkey)
                .unwrap_or_default(),
        ))
    }

    pub fn input(input: &SppProofInputUtxo) -> Result<Self, RingError> {
        let real = !input.is_dummy() && !input.is_address();
        Ok(Self::with_owner(
            ProofInputUtxo::try_from(input)?,
            match real {
                true => input.utxo.owner.owner_proof_input_hash()?,
                false => [0; 32],
            },
            match real {
                true => input.nullifier_pubkey,
                false => [0; 32],
            },
        ))
    }

    fn with_owner(fields: ProofInputUtxo, owner_pk_hash: [u8; 32], nullifier_pk: [u8; 32]) -> Self {
        Self {
            domain: fields.domain,
            tree_id: fields.tree_id,
            owner_pk_hash,
            nullifier_pk,
            asset: fields.asset,
            amount: fields.amount,
            blinding: fields.blinding,
            data_hash: fields.data_hash,
            ring_data_hash: fields.ring_data_hash,
            ring_program_id: fields.ring_program_id,
        }
    }
}

/// The audit head's witness, shared by every audit circuit.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuditParams {
    #[serde(with = "fe")]
    pub first_nullifier: [u8; 32],
    #[serde(with = "fe")]
    pub ring_id: [u8; 32],
    #[serde(serialize_with = "fe::zeroizing")]
    pub tx_viewing_sk: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "fe::zeroizing")]
    pub eph_sk: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "coordinate")]
    pub auditor_pk: X25519Pubkey,
    #[serde(with = "fe")]
    pub salt: [u8; 16],
    #[serde(with = "fe")]
    pub seed_out: [u8; 32],
    /// The statement's layout flags.
    pub layout: u8,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PackedAudit {
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(flatten)]
    pub audit: AuditParams,
    pub n_out: u8,
    /// The key's capacity, slots past `n_out` zero.
    pub outputs: Vec<Opening>,
    #[serde(serialize_with = "fe::seq")]
    pub owner_keys: Vec<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeliveredOutput {
    pub output: Opening,
    #[serde(with = "fe")]
    pub asset_address: [u8; 32],
    #[serde(with = "fe")]
    pub recipient_key: [u8; 32],
    #[serde(with = "fe")]
    pub owner_key: [u8; 32],
    #[serde(with = "fe")]
    pub body: [u8; RING_DELIVERED_BODY_LEN],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeliveredAudit {
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(flatten)]
    pub audit: AuditParams,
    pub outputs: Vec<DeliveredOutput>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Stream {
    #[serde(with = "fe")]
    pub tag: [u8; 32],
    pub inbox: bool,
    pub pair: bool,
    #[serde(rename = "self")]
    pub change: bool,
    pub index: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct AnonymousOutput {
    #[serde(flatten)]
    pub delivered: DeliveredOutput,
    pub stream: Stream,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Anchor {
    #[serde(with = "fe")]
    pub tree_id: [u8; 32],
    #[serde(with = "fe")]
    pub asset: [u8; 32],
    #[serde(with = "fe")]
    pub amount: [u8; 32],
    #[serde(with = "fe")]
    pub slot_secret: [u8; 32],
    #[serde(with = "fe")]
    pub first_nullifier: [u8; 32],
    pub slot_index: u8,
    pub epoch: u64,
    pub index: u8,
    pub path_index: u64,
    #[serde(serialize_with = "fe::seq")]
    pub path: Vec<[u8; 32]>,
}

/// The slot secret opens the payment and its pair stream.
impl core::fmt::Debug for Anchor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Self {
            tree_id,
            asset,
            amount,
            slot_secret: _,
            first_nullifier,
            slot_index,
            epoch,
            index,
            path_index,
            path,
        } = self;
        f.debug_struct("Anchor")
            .field("tree_id", tree_id)
            .field("asset", asset)
            .field("amount", amount)
            .field("slot_secret", &REDACTED)
            .field("first_nullifier", first_nullifier)
            .field("slot_index", slot_index)
            .field("epoch", epoch)
            .field("index", index)
            .field("path_index", path_index)
            .field("path", path)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AnonymousAudit {
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(flatten)]
    pub audit: AuditParams,
    pub outputs: Vec<AnonymousOutput>,
    #[serde(with = "fe")]
    pub private_tx_hash: [u8; 32],
    #[serde(with = "fe")]
    pub private_tx_blinding: [u8; 32],
    #[serde(with = "fe")]
    pub sender_key: [u8; 32],
    pub input_count: u8,
    /// The input class, slots past `input_count` zero.
    pub inputs: Vec<Opening>,
    #[serde(with = "fe")]
    pub sender_commitment: [u8; 32],
    pub epoch: u64,
    #[serde(with = "fe")]
    pub first_contact_root: [u8; 32],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor: Option<Anchor>,
}

/// A member's record, or the low record proving it absent, as one subject entry opens it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MemberOpening {
    pub present: bool,
    #[serde(with = "fe")]
    pub next: [u8; 32],
    pub lists: u64,
    #[serde(with = "fe")]
    pub escrow_key: [u8; 32],
    pub index: u64,
    #[serde(serialize_with = "path")]
    pub path: QuadPath,
    #[serde(with = "fe")]
    pub low_member: [u8; 32],
    #[serde(with = "fe")]
    pub low_next: [u8; 32],
    pub low_lists: u64,
    #[serde(with = "fe")]
    pub low_escrow: [u8; 32],
}

impl From<&RecordOpening> for MemberOpening {
    fn from(opening: &RecordOpening) -> Self {
        match opening {
            RecordOpening::Present { record, path } => Self {
                present: true,
                next: record.next,
                lists: record.lists,
                escrow_key: record.escrow_key,
                index: path.index,
                path: *path,
                low_member: [0; 32],
                low_next: [0; 32],
                low_lists: 0,
                low_escrow: [0; 32],
            },
            RecordOpening::Absent { low, path } => Self {
                present: false,
                next: [0; 32],
                lists: 0,
                escrow_key: [0; 32],
                index: path.index,
                path: *path,
                low_member: low.member,
                low_next: low.next,
                low_lists: low.lists,
                low_escrow: low.escrow_key,
            },
        }
    }
}

/// One subject's openings, `None` where the circuit reads no record.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Entry {
    pub own: Option<MemberOpening>,
    pub curator: Option<MemberOpening>,
}

pub(crate) struct PolicyTable<'a> {
    pub rules: &'a EncodedRuleTable,
    pub sources: &'a SourceMap,
}

impl Serialize for PolicyTable<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Source {
            list_id: u8,
            #[serde(with = "fe")]
            registry: [u8; 32],
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Limit {
            #[serde(with = "fe")]
            asset: [u8; 32],
            #[serde(with = "fe")]
            cap: [u8; 32],
            #[serde(with = "fe")]
            cosign_above: [u8; 32],
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Table<'a> {
            sources: [Source; MAX_SOURCES],
            policy_len: u8,
            #[serde(serialize_with = "fe::seq")]
            rules: &'a [[u8; 32]],
            #[serde(serialize_with = "fe::seq")]
            inline_assets: &'a [[u8; 32]],
            #[serde(serialize_with = "fe::seq")]
            inline_limits: Vec<[u8; 32]>,
            inline_count: u8,
            limits: Vec<Limit>,
            limit_count: u8,
        }
        use zolana_hasher::primitives::right_align;
        let rules = self.rules;
        let slots = self.sources.slots();
        Table {
            sources: core::array::from_fn(|i| Source {
                list_id: slots[i].list_id,
                registry: slots[i].registry,
            }),
            policy_len: rules.rule_count,
            rules: &rules.rules,
            inline_assets: &rules.inline_assets,
            inline_limits: rules.inline_limits.iter().map(right_align).collect(),
            inline_count: rules.inline_count,
            limits: rules
                .limit_assets
                .iter()
                .zip(&rules.limit_caps)
                .zip(&rules.limit_cosign)
                .map(|((asset, cap), cosign)| Limit {
                    asset: *asset,
                    cap: right_align(cap),
                    cosign_above: right_align(cosign),
                })
                .collect(),
            limit_count: rules.limit_count,
        }
        .serialize(serializer)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OutputOpening {
    #[serde(flatten)]
    pub opening: Opening,
    #[serde(with = "option_field", skip_serializing_if = "Option::is_none")]
    pub ct_hash: Option<[u8; 32]>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PolicyParams<'a> {
    #[serde(with = "fe")]
    pub private_tx_hash: [u8; 32],
    #[serde(with = "fe")]
    pub policy_hash: [u8; 32],
    #[serde(with = "fe")]
    pub ring_id: [u8; 32],
    #[serde(with = "fe")]
    pub own_root: [u8; 32],
    #[serde(with = "fe")]
    pub curator_root: [u8; 32],
    #[serde(serialize_with = "fe::seq")]
    pub public_assets: Vec<[u8; 32]>,
    #[serde(serialize_with = "fe::seq")]
    pub public_amounts: Vec<[u8; 32]>,
    #[serde(flatten)]
    pub table: PolicyTable<'a>,
    #[serde(with = "fe")]
    pub address_chain: [u8; 32],
    #[serde(with = "fe")]
    pub private_tx_blinding: [u8; 32],
    pub outputs: Vec<OutputOpening>,
    #[serde(with = "fe")]
    pub sender_pk_hash: [u8; 32],
    pub sender_entry: Entry,
    pub owner_entries: Vec<Entry>,
    pub asset_entries: Vec<Entry>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MemberPolicy<'a> {
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    pub anonymous: bool,
    pub approval_required: bool,
    pub key_escrow: bool,
    #[serde(with = "fe")]
    pub sender: [u8; 32],
    #[serde(with = "fe")]
    pub input_chain: [u8; 32],
    #[serde(flatten)]
    pub policy: PolicyParams<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DelegatePolicy<'a> {
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    pub inputs: Vec<Opening>,
    #[serde(flatten)]
    pub policy: PolicyParams<'a>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordWrite {
    pub entry: QueueEntryRequest,
    pub exists: bool,
    #[serde(with = "fe")]
    pub old_next: [u8; 32],
    pub old_lists: u64,
    #[serde(with = "fe")]
    pub old_escrow: [u8; 32],
    pub index: u64,
    #[serde(serialize_with = "path")]
    pub path: QuadPath,
    #[serde(with = "fe")]
    pub low_member: [u8; 32],
    #[serde(with = "fe")]
    pub low_next: [u8; 32],
    pub low_lists: u64,
    #[serde(with = "fe")]
    pub low_escrow: [u8; 32],
    pub low_index: u64,
    #[serde(serialize_with = "path")]
    pub low_path: QuadPath,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QueueEntryRequest {
    #[serde(with = "fe")]
    pub member: [u8; 32],
    pub mask: u64,
    pub value: u64,
    #[serde(with = "fe")]
    pub escrow_key: [u8; 32],
}

impl From<&QueueEntry> for QueueEntryRequest {
    fn from(entry: &QueueEntry) -> Self {
        Self {
            member: entry.member,
            mask: entry.mask,
            value: entry.value,
            escrow_key: entry.escrow_key,
        }
    }
}

impl From<&RecordWriteProofInput> for RecordWrite {
    fn from(write: &RecordWriteProofInput) -> Self {
        let MemberRecord {
            member: low_member,
            next: low_next,
            lists: low_lists,
            escrow_key: low_escrow,
        } = write.low;
        Self {
            entry: (&write.entry).into(),
            exists: write.exists,
            old_next: write.old_next,
            old_lists: write.old_lists,
            old_escrow: write.old_escrow,
            index: write.slot.index,
            path: write.slot,
            low_member,
            low_next,
            low_lists,
            low_escrow,
            low_index: write.low_path.index,
            low_path: write.low_path,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApplyRecords {
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(with = "fe")]
    pub old_root: [u8; 32],
    #[serde(with = "fe")]
    pub new_root: [u8; 32],
    pub old_next_index: u32,
    pub new_next_index: u32,
    #[serde(with = "fe")]
    pub chain_start: [u8; 32],
    #[serde(with = "fe")]
    pub chain_end: [u8; 32],
    pub count: u8,
    /// The key's batch, writes past `count` assign zeros.
    pub writes: Vec<Option<RecordWrite>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyRegister {
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(with = "fe")]
    pub member: [u8; 32],
    #[serde(serialize_with = "fe::zeroizing")]
    pub nullifier_secret: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "fe::zeroizing")]
    pub eph_sk: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "coordinate")]
    pub auditor_pk: X25519Pubkey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MergeSlot {
    #[serde(with = "fe")]
    pub domain: [u8; 32],
    #[serde(with = "fe")]
    pub tree_id: [u8; 32],
    #[serde(with = "fe")]
    pub amount: [u8; 32],
    #[serde(with = "fe")]
    pub blinding: [u8; 32],
    #[serde(with = "fe")]
    pub ring_data_hash: [u8; 32],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MergeAnonymous {
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(with = "fe")]
    pub private_tx_hash: [u8; 32],
    #[serde(with = "fe")]
    pub output_utxo_hash: [u8; 32],
    #[serde(with = "fe")]
    pub first_nullifier: [u8; 32],
    #[serde(with = "fe")]
    pub ring_program_id: [u8; 32],
    #[serde(serialize_with = "coordinate")]
    pub auditor_pk: X25519Pubkey,
    /// The SPP output ciphertext salt right aligned.
    #[serde(with = "fe")]
    pub salt: [u8; 32],
    #[serde(serialize_with = "fe::zeroizing")]
    pub eph_sk: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "fe::zeroizing")]
    pub disclosure_key: Zeroizing<[u8; 32]>,
    #[serde(with = "fe")]
    pub owner_key: [u8; 32],
    #[serde(serialize_with = "fe::zeroizing")]
    pub nullifier_secret: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "fe::seq")]
    pub mint_chunks: [[u8; 32]; 2],
    pub inputs: Vec<MergeSlot>,
    #[serde(with = "fe")]
    pub output_tree_id: [u8; 32],
    #[serde(with = "fe")]
    pub output_ring_data_hash: [u8; 32],
}

/// A present record as the deposit circuit opens it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordOpeningRequest {
    #[serde(with = "fe")]
    pub next: [u8; 32],
    pub lists: u64,
    #[serde(with = "fe")]
    pub escrow_key: [u8; 32],
    pub index: u64,
    #[serde(serialize_with = "path")]
    pub path: QuadPath,
}

impl RecordOpeningRequest {
    pub fn present(record: &MemberRecord, path: &QuadPath) -> Self {
        Self {
            next: record.next,
            lists: record.lists,
            escrow_key: record.escrow_key,
            index: path.index,
            path: *path,
        }
    }
}

/// The audited deposit's witness, one slot per deposited note.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DepositRequest {
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(with = "fe")]
    pub context_hash: [u8; 32],
    pub count: u32,
    #[serde(skip_serializing_if = "core::ops::Not::not")]
    pub anonymous: bool,
    #[serde(serialize_with = "fe::seq")]
    pub owner_pk_hashes: [[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    #[serde(serialize_with = "option_seq", skip_serializing_if = "Option::is_none")]
    pub owner_keys: Option<[[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS]>,
    #[serde(serialize_with = "fe::seq")]
    pub nullifier_pks: [[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    #[serde(serialize_with = "zeroizing_seq")]
    pub blinding_secrets: Zeroizing<[[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS]>,
    #[serde(serialize_with = "fe::seq")]
    pub ct_hashes: [[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    pub members: [Option<RecordOpeningRequest>; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    #[serde(serialize_with = "fe::zeroizing")]
    pub eph_sk: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "coordinate")]
    pub auditor_pk: X25519Pubkey,
    pub key_escrow: bool,
    #[serde(with = "fe")]
    pub member_registry_root: [u8; 32],
}

/// The Solana key an owner identity hashes, the disclosure names it.
pub(crate) fn owner_key(owner: &PublicKey) -> Result<[u8; 32], RingError> {
    Ok(owner.confidential_view_tag()?)
}

/// The circuits witness the untagged 32-byte coordinate.
fn coordinate<S: Serializer>(key: &X25519Pubkey, serializer: S) -> Result<S::Ok, S::Error> {
    fe::bytes(&key.u(), serializer)
}

/// Every level's siblings from the leaf up, in child order.
fn path<S: Serializer>(path: &QuadPath, serializer: S) -> Result<S::Ok, S::Error> {
    let flat: Vec<[u8; 32]> = path
        .siblings
        .iter()
        .flat_map(|level: &[[u8; 32]; QUAD_ARITY - 1]| level.iter().copied())
        .collect();
    fe::seq(&flat, serializer)
}

fn option_seq<S: Serializer, const N: usize>(
    values: &Option<[[u8; 32]; N]>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match values {
        Some(values) => fe::seq(values, serializer),
        None => serializer.serialize_none(),
    }
}

fn zeroizing_seq<S: Serializer, const N: usize>(
    values: &Zeroizing<[[u8; 32]; N]>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    fe::seq(values.as_slice(), serializer)
}

mod option_field {
    use serde::Serializer;

    use crate::prover::fe;

    pub(crate) fn serialize<S: Serializer>(
        value: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => fe::bytes(value, serializer),
            None => serializer.serialize_none(),
        }
    }
}
