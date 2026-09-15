//! The prover wire of the ring circuit. The audit fields are the audit
//! request's, the policy fields open the transaction's slots and the entries
//! the rules are checked against.

use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::Serialize;
use zeroize::Zeroizing;
use zolana_client::{
    prover::{Delivery, ProveRequest},
    ClientError,
};
use zolana_interface::tree_slot::tree_id_field;
use zolana_keypair::{P256Pubkey, ViewingKey};
use zolana_ring_policy::{
    VelocityRow, MAX_INLINE_ASSETS, MAX_RULES, MAX_SOURCES, MAX_VELOCITY_ASSETS,
    POLICY_INPUT_SLOTS, POLICY_OUTPUT_SLOTS,
};

use crate::{head_map::HeadWitness, velocity::RowCharges};

use crate::{
    instructions::transact::request::{bytes_to_hex, field_hex, index_hex, json_body, SecretHex},
    CustomRing, TransferError,
};

pub const STATE_PATH_LEN: usize = 32;
pub const NULLIFIER_PATH_LEN: usize = 40;

/// One opened UTXO slot, in the order the circuit hashes it.
#[derive(Clone, Copy, Debug, Default)]
pub struct CustomRingOpening {
    pub domain: [u8; 32],
    /// Raw id of the tree the slot hashes under, right aligned.
    pub tree_id: [u8; 32],
    pub owner_pk_hash: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub asset: [u8; 32],
    pub amount: [u8; 32],
    pub blinding: [u8; 32],
    pub data_hash: [u8; 32],
    pub ring_data_hash: [u8; 32],
    pub ring_program_id: [u8; 32],
}

/// One entry fact, proven against the two roots the program resolved.
#[derive(Clone, Debug)]
pub struct RuleAnswer {
    pub enabled: bool,
    pub mode: u8,
    pub list_id: u8,
    pub state: u8,
    pub absent_branch: u8,
    pub member: [u8; 32],
    pub content_hash: [u8; 32],
    pub version: u64,
    pub blinding: [u8; 32],
    pub low: [u8; 32],
    pub next: [u8; 32],
    pub nullifier_path: Vec<[u8; 32]>,
    pub nullifier_path_index: u64,
    pub state_path: Vec<[u8; 32]>,
    pub state_path_index: u64,
}

impl Default for RuleAnswer {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: 1,
            list_id: 1,
            state: 1,
            absent_branch: 1,
            member: [0u8; 32],
            content_hash: [0u8; 32],
            version: 0,
            blinding: [0u8; 32],
            low: [0u8; 32],
            next: [0u8; 32],
            nullifier_path: vec![[0u8; 32]; NULLIFIER_PATH_LEN],
            nullifier_path_index: 0,
            state_path: vec![[0u8; 32]; STATE_PATH_LEN],
            state_path_index: 0,
        }
    }
}

/// One positional source slot, slot `i` is empty or serves list `i + 1`.
pub use zolana_ring_policy::SourceOwner as SourceOwnerEntry;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SpendRecordProofInput {
    pub version: u64,
    pub window: u64,
    pub commitment: [u8; 32],
    pub salt: [u8; 32],
    pub assets: [[u8; 32]; MAX_VELOCITY_ASSETS],
    pub spent: [u64; MAX_VELOCITY_ASSETS],
    pub next_salt: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingIdentity {
    pub ring_id: [u8; 32],
    pub namespace_owner_hash: [u8; 32],
}

impl RingIdentity {
    pub(crate) fn new(
        ring: CustomRing,
        namespace_owner_hash: [u8; 32],
    ) -> Result<Self, TransferError> {
        Ok(Self {
            ring_id: zolana_ring_policy::ring_id_field(ring.program_id().as_array())
                .map_err(|_| TransferError::PolicyHashing)?,
            namespace_owner_hash,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProvedWindow {
    pub slots: u64,
    pub index: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VelocityProofInput {
    pub window_slots: u64,
    pub rows: [VelocityRow; MAX_VELOCITY_ASSETS],
    pub row_count: u8,
    pub ring_id: [u8; 32],
    pub namespace_owner_hash: [u8; 32],
    pub window_index: u64,
    pub approval_required: bool,
    pub record: SpendRecordProofInput,
}

impl VelocityProofInput {
    /// Rows without a window carry the charges, no record accompanies them.
    pub(crate) fn per_transfer(charges: &RowCharges, identity: RingIdentity) -> Self {
        Self {
            window_slots: 0,
            rows: charges.rows,
            row_count: charges.row_count,
            ring_id: identity.ring_id,
            namespace_owner_hash: identity.namespace_owner_hash,
            window_index: 0,
            approval_required: charges.approval_required,
            record: SpendRecordProofInput::default(),
        }
    }

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

    pub(crate) fn window(&self) -> Option<ProvedWindow> {
        (self.window_slots != 0).then_some(ProvedWindow {
            slots: self.window_slots,
            index: self.window_index,
        })
    }
}

pub struct CustomRingPolicyProofRequest {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub tx_viewing_key: ViewingKey,
    pub ephemeral_key: ViewingKey,
    pub auditor_key: P256Pubkey,
    pub n_in: u8,
    pub n_out: u8,
    pub inputs: [CustomRingOpening; POLICY_INPUT_SLOTS],
    pub outputs: [CustomRingOpening; POLICY_OUTPUT_SLOTS],
    pub address_chain: [u8; 32],
    pub external_data_hash: [u8; 32],
    pub private_tx_blinding: [u8; 32],
    pub sources: [SourceOwnerEntry; MAX_SOURCES],
    pub policy_len: u8,
    pub rules: [[u8; 32]; MAX_RULES],
    pub inline_assets: [[u8; 32]; MAX_INLINE_ASSETS],
    pub inline_limits: [u64; MAX_INLINE_ASSETS],
    pub inline_count: u8,
    pub state_root: [u8; 32],
    pub nullifier_root: [u8; 32],
    pub entries_tree_id: u16,
    pub velocity: VelocityProofInput,
    pub answers: Vec<RuleAnswer>,
}

/// Request for the base custom-ring statement, without policy enforcement.
pub struct CustomRingBaseProofRequest {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub tx_viewing_key: ViewingKey,
    pub ephemeral_key: ViewingKey,
    pub auditor_key: P256Pubkey,
}

impl ProveRequest for CustomRingBaseProofRequest {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        let tx_viewing_secret = self.tx_viewing_key.secret_bytes();
        let ephemeral_secret = self.ephemeral_key.secret_bytes();
        let auditor_key = self
            .auditor_key
            .to_p256()
            .map_err(|_| ClientError::Prover("invalid audit public key".to_string()))?;
        let auditor_pk = auditor_key.to_encoded_point(false);
        let json = CustomRingBaseProofRequestJson {
            circuit_type: "custom-ring-base",
            public_input_hash: field_hex(&self.public_input_hash),
            private_tx_hash: field_hex(&self.private_tx_hash),
            tx_viewing_sk: SecretHex::new(tx_viewing_secret.as_slice()),
            eph_sk: SecretHex::new(ephemeral_secret.as_slice()),
            auditor_pk: bytes_to_hex(auditor_pk.as_bytes()),
        };
        serde_json::to_string(&json)
            .map(Zeroizing::new)
            .map_err(|_| ClientError::Prover("base request serialization failed".to_string()))
    }

    fn delivery(&self) -> Delivery {
        Delivery::Queued
    }
}

#[derive(Serialize)]
struct CustomRingBaseProofRequestJson {
    #[serde(rename = "circuitType")]
    circuit_type: &'static str,
    #[serde(rename = "publicInputHash")]
    public_input_hash: String,
    #[serde(rename = "privateTxHash")]
    private_tx_hash: String,
    #[serde(rename = "txViewingSk")]
    tx_viewing_sk: SecretHex,
    #[serde(rename = "ephSk")]
    eph_sk: SecretHex,
    #[serde(rename = "auditorPk")]
    auditor_pk: String,
}

impl CustomRingPolicyProofRequest {
    pub(crate) fn json(&self) -> Result<CustomRingPolicyProofRequestJson, ClientError> {
        let tx_viewing_secret = self.tx_viewing_key.secret_bytes();
        let ephemeral_secret = self.ephemeral_key.secret_bytes();
        let auditor_key = self
            .auditor_key
            .to_p256()
            .map_err(|_| ClientError::Prover("invalid audit public key".to_string()))?;
        let auditor_pk = auditor_key.to_encoded_point(false);
        Ok(CustomRingPolicyProofRequestJson {
            circuit_type: "custom-ring-policy",
            public_input_hash: field_hex(&self.public_input_hash),
            private_tx_hash: field_hex(&self.private_tx_hash),
            tx_viewing_sk: SecretHex::new(tx_viewing_secret.as_slice()),
            eph_sk: SecretHex::new(ephemeral_secret.as_slice()),
            auditor_pk: bytes_to_hex(auditor_pk.as_bytes()),
            n_in: self.n_in,
            n_out: self.n_out,
            inputs: self.inputs.iter().map(opening_json).collect(),
            outputs: self.outputs.iter().map(opening_json).collect(),
            address_chain: field_hex(&self.address_chain),
            external_data_hash: field_hex(&self.external_data_hash),
            private_tx_blinding: field_hex(&self.private_tx_blinding),
            sources: self.sources.iter().map(source_json).collect(),
            policy_len: self.policy_len,
            rule_enc: self.rules.iter().map(field_hex).collect(),
            inline_assets: self.inline_assets.iter().map(field_hex).collect(),
            inline_limits: self.inline_limits.iter().map(limit_hex).collect(),
            inline_count: self.inline_count,
            state_root: field_hex(&self.state_root),
            nullifier_root: field_hex(&self.nullifier_root),
            entries_tree_id: field_hex(&tree_id_field(self.entries_tree_id)),
            window_slots: self.velocity.window_slots,
            velocity: self.velocity.rows.iter().map(velocity_row_json).collect(),
            velocity_count: self.velocity.row_count,
            ring_id: field_hex(&self.velocity.ring_id),
            namespace_owner_hash: field_hex(&self.velocity.namespace_owner_hash),
            window_index: self.velocity.window_index,
            approval_required: self.velocity.approval_required,
            record: record_json(&self.velocity.record),
            answers: self.answers.iter().map(answers_json).collect(),
        })
    }
}

impl ProveRequest for CustomRingPolicyProofRequest {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        json_body(&self.json()?)
    }

    fn delivery(&self) -> Delivery {
        Delivery::Queued
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HeadTransitionJson {
    head_old_root: String,
    head_new_root: String,
    head_next: String,
    head_index: String,
    head_proof: Vec<String>,
}

impl HeadTransitionJson {
    pub(crate) fn new(
        witness: &HeadWitness,
        transition: &custom_ring_interface::HeadMapTransition,
    ) -> Self {
        Self {
            head_old_root: field_hex(&transition.old_root),
            head_new_root: field_hex(&transition.new_root),
            head_next: field_hex(&witness.next),
            head_index: index_hex(witness.index),
            head_proof: witness.proof.iter().map(field_hex).collect(),
        }
    }
}

fn opening_json(opening: &CustomRingOpening) -> CustomRingOpeningJson {
    CustomRingOpeningJson {
        domain: field_hex(&opening.domain),
        tree_id: field_hex(&opening.tree_id),
        owner_pk_hash: field_hex(&opening.owner_pk_hash),
        nullifier_pk: field_hex(&opening.nullifier_pk),
        asset: field_hex(&opening.asset),
        amount: field_hex(&opening.amount),
        blinding: field_hex(&opening.blinding),
        data_hash: field_hex(&opening.data_hash),
        ring_data_hash: field_hex(&opening.ring_data_hash),
        ring_program_id: field_hex(&opening.ring_program_id),
    }
}

fn source_json(source: &SourceOwnerEntry) -> CustomRingSourceJson {
    CustomRingSourceJson {
        list_id: source.list_id,
        owner_hash: field_hex(&source.owner_hash),
    }
}

fn limit_hex(limit: &u64) -> String {
    let mut field = [0u8; 32];
    field[24..].copy_from_slice(&limit.to_be_bytes());
    field_hex(&field)
}

fn velocity_row_json(row: &VelocityRow) -> VelocityRowJson {
    VelocityRowJson {
        asset: field_hex(&row.asset),
        cap: limit_hex(&row.cap),
        cosign_above: limit_hex(&row.cosign_above),
    }
}

fn record_json(record: &SpendRecordProofInput) -> SpendRecordJson {
    SpendRecordJson {
        version: record.version,
        window: record.window,
        commitment: field_hex(&record.commitment),
        salt: field_hex(&record.salt),
        assets: record.assets.iter().map(field_hex).collect(),
        spent: record.spent.iter().map(limit_hex).collect(),
        next_salt: field_hex(&record.next_salt),
    }
}

fn answers_json(entry: &RuleAnswer) -> RuleAnswerJson {
    RuleAnswerJson {
        enabled: entry.enabled,
        mode: entry.mode,
        list_id: entry.list_id,
        state: entry.state,
        absent_branch: entry.absent_branch,
        member: field_hex(&entry.member),
        content_hash: field_hex(&entry.content_hash),
        version: entry.version,
        blinding: field_hex(&entry.blinding),
        low: field_hex(&entry.low),
        next: field_hex(&entry.next),
        nf_path_elements: entry.nullifier_path.iter().map(field_hex).collect(),
        nf_path_index: entry.nullifier_path_index,
        state_path_elements: entry.state_path.iter().map(field_hex).collect(),
        state_path_index: entry.state_path_index,
    }
}

#[derive(Serialize)]
struct CustomRingOpeningJson {
    domain: String,
    #[serde(rename = "treeId")]
    tree_id: String,
    #[serde(rename = "ownerPkHash")]
    owner_pk_hash: String,
    #[serde(rename = "nullifierPk")]
    nullifier_pk: String,
    asset: String,
    amount: String,
    blinding: String,
    #[serde(rename = "dataHash")]
    data_hash: String,
    #[serde(rename = "ringDataHash")]
    ring_data_hash: String,
    #[serde(rename = "ringProgramId")]
    ring_program_id: String,
}

#[derive(Serialize)]
struct CustomRingSourceJson {
    #[serde(rename = "listId")]
    list_id: u8,
    #[serde(rename = "ownerHash")]
    owner_hash: String,
}

#[derive(Serialize)]
struct VelocityRowJson {
    asset: String,
    cap: String,
    #[serde(rename = "cosignAbove")]
    cosign_above: String,
}

#[derive(Serialize)]
struct SpendRecordJson {
    version: u64,
    window: u64,
    commitment: String,
    salt: String,
    assets: Vec<String>,
    spent: Vec<String>,
    #[serde(rename = "nextSalt")]
    next_salt: String,
}

#[derive(Serialize)]
struct RuleAnswerJson {
    enabled: bool,
    mode: u8,
    #[serde(rename = "listId")]
    list_id: u8,
    state: u8,
    #[serde(rename = "absentBranch")]
    absent_branch: u8,
    member: String,
    #[serde(rename = "contentHash")]
    content_hash: String,
    version: u64,
    blinding: String,
    low: String,
    next: String,
    #[serde(rename = "nfPathElements")]
    nf_path_elements: Vec<String>,
    #[serde(rename = "nfPathIndex")]
    nf_path_index: u64,
    #[serde(rename = "statePathElements")]
    state_path_elements: Vec<String>,
    #[serde(rename = "statePathIndex")]
    state_path_index: u64,
}

#[derive(Serialize)]
pub(crate) struct CustomRingPolicyProofRequestJson {
    #[serde(rename = "circuitType")]
    circuit_type: &'static str,
    #[serde(rename = "publicInputHash")]
    public_input_hash: String,
    #[serde(rename = "privateTxHash")]
    private_tx_hash: String,
    #[serde(rename = "txViewingSk")]
    tx_viewing_sk: SecretHex,
    #[serde(rename = "ephSk")]
    eph_sk: SecretHex,
    #[serde(rename = "auditorPk")]
    auditor_pk: String,
    #[serde(rename = "nIn")]
    n_in: u8,
    #[serde(rename = "nOut")]
    n_out: u8,
    inputs: Vec<CustomRingOpeningJson>,
    outputs: Vec<CustomRingOpeningJson>,
    #[serde(rename = "addressChain")]
    address_chain: String,
    #[serde(rename = "externalDataHash")]
    external_data_hash: String,
    #[serde(rename = "privateTxBlinding")]
    private_tx_blinding: String,
    sources: Vec<CustomRingSourceJson>,
    #[serde(rename = "policyLen")]
    policy_len: u8,
    #[serde(rename = "ruleEnc")]
    rule_enc: Vec<String>,
    #[serde(rename = "inlineAssets")]
    inline_assets: Vec<String>,
    #[serde(rename = "inlineLimits")]
    inline_limits: Vec<String>,
    #[serde(rename = "inlineCount")]
    inline_count: u8,
    #[serde(rename = "stateRoot")]
    state_root: String,
    #[serde(rename = "nullifierRoot")]
    nullifier_root: String,
    #[serde(rename = "entriesTreeId")]
    entries_tree_id: String,
    #[serde(rename = "windowSlots")]
    window_slots: u64,
    velocity: Vec<VelocityRowJson>,
    #[serde(rename = "velocityCount")]
    velocity_count: u8,
    #[serde(rename = "ringId")]
    ring_id: String,
    #[serde(rename = "namespaceOwnerHash")]
    namespace_owner_hash: String,
    #[serde(rename = "windowIndex")]
    window_index: u64,
    #[serde(rename = "approvalRequired")]
    approval_required: bool,
    record: SpendRecordJson,
    answers: Vec<RuleAnswerJson>,
}

#[cfg(test)]
mod tests {
    use zolana_ring_policy::ANSWER_SLOTS;

    use super::*;

    fn request() -> CustomRingPolicyProofRequest {
        CustomRingPolicyProofRequest {
            public_input_hash: [1u8; 32],
            private_tx_hash: [2u8; 32],
            tx_viewing_key: ViewingKey::from_bytes(&[3u8; 32]).expect("viewing key"),
            ephemeral_key: ViewingKey::from_bytes(&[4u8; 32]).expect("ephemeral key"),
            auditor_key: ViewingKey::from_bytes(&[5u8; 32])
                .expect("auditor key")
                .pubkey(),
            n_in: 2,
            n_out: 2,
            inputs: [CustomRingOpening::default(); POLICY_INPUT_SLOTS],
            outputs: [CustomRingOpening::default(); POLICY_OUTPUT_SLOTS],
            address_chain: [0u8; 32],
            external_data_hash: [6u8; 32],
            private_tx_blinding: [7u8; 32],
            sources: [SourceOwnerEntry::default(); MAX_SOURCES],
            policy_len: 1,
            rules: [[0u8; 32]; MAX_RULES],
            inline_assets: [[0u8; 32]; MAX_INLINE_ASSETS],
            inline_limits: [0; MAX_INLINE_ASSETS],
            inline_count: 0,
            state_root: [8u8; 32],
            nullifier_root: [9u8; 32],
            entries_tree_id: 3,
            velocity: VelocityProofInput::off(RingIdentity {
                ring_id: [10u8; 32],
                namespace_owner_hash: [11u8; 32],
            }),
            answers: vec![RuleAnswer::default(); ANSWER_SLOTS],
        }
    }

    #[test]
    fn the_request_matches_the_server_wire_format() {
        let body = request().body().expect("body");
        let value: serde_json::Value = serde_json::from_str(&body).expect("json");
        let object = value.as_object().expect("object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "addressChain",
                "answers",
                "approvalRequired",
                "auditorPk",
                "circuitType",
                "entriesTreeId",
                "ephSk",
                "externalDataHash",
                "inlineAssets",
                "inlineCount",
                "inlineLimits",
                "inputs",
                "nIn",
                "nOut",
                "namespaceOwnerHash",
                "nullifierRoot",
                "outputs",
                "policyLen",
                "privateTxBlinding",
                "privateTxHash",
                "publicInputHash",
                "record",
                "ringId",
                "ruleEnc",
                "sources",
                "stateRoot",
                "txViewingSk",
                "velocity",
                "velocityCount",
                "windowIndex",
                "windowSlots",
            ]
        );
        assert_eq!(object["circuitType"], "custom-ring-policy");
        assert_eq!(
            object["ruleEnc"].as_array().expect("rules").len(),
            MAX_RULES
        );
        assert_eq!(
            object["answers"].as_array().expect("answers").len(),
            ANSWER_SLOTS
        );
        assert_eq!(
            object["sources"].as_array().expect("sources").len(),
            MAX_SOURCES
        );
        let mut slot_keys: Vec<&str> = object["sources"][0]
            .as_object()
            .expect("slot")
            .keys()
            .map(String::as_str)
            .collect();
        slot_keys.sort_unstable();
        assert_eq!(slot_keys, ["listId", "ownerHash"]);
        assert_eq!(
            object["velocity"].as_array().expect("rows").len(),
            MAX_VELOCITY_ASSETS
        );
        let mut record_keys: Vec<&str> = object["record"]
            .as_object()
            .expect("record")
            .keys()
            .map(String::as_str)
            .collect();
        record_keys.sort_unstable();
        assert_eq!(
            record_keys,
            [
                "assets",
                "commitment",
                "nextSalt",
                "salt",
                "spent",
                "version",
                "window"
            ]
        );
    }

    #[test]
    fn every_field_element_is_canonical_hex() {
        let body = request().body().expect("body");
        let value: serde_json::Value = serde_json::from_str(&body).expect("json");
        let entry = &value["answers"][0];
        assert_eq!(
            entry["nfPathElements"].as_array().expect("path").len(),
            NULLIFIER_PATH_LEN
        );
        assert_eq!(
            entry["statePathElements"].as_array().expect("path").len(),
            STATE_PATH_LEN
        );
        let hash = value["publicInputHash"].as_str().expect("hash");
        assert_eq!(hash.len(), 66);
        assert!(hash.starts_with("0x") && hash.to_lowercase() == hash);
    }
}
