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
use zolana_keypair::{P256Pubkey, ViewingKey};
use zolana_ring_policy::{MAX_INLINE_ASSETS, MAX_RULES, MAX_SOURCES};

use crate::instructions::transact::request::{bytes_to_hex, field_hex, SecretHex};

/// Slots the answers array proves in one transaction, a transfer needing more must be
/// split.
pub const ANSWER_SLOTS: usize = 10;
pub const POLICY_INPUT_SLOTS: usize = 5;
pub const POLICY_OUTPUT_SLOTS: usize = 4;
pub const STATE_PATH_LEN: usize = 32;
pub const NULLIFIER_PATH_LEN: usize = 40;

/// One opened UTXO slot, in the order the circuit hashes it.
#[derive(Clone, Copy, Debug, Default)]
pub struct CustomRingOpening {
    pub domain: [u8; 32],
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
#[derive(Clone, Copy, Debug, Default)]
pub struct SourceOwnerEntry {
    pub list_id: u8,
    pub owner_hash: [u8; 32],
}

pub struct CustomRingProofRequest {
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
    pub sources: [SourceOwnerEntry; MAX_SOURCES],
    pub policy_len: u8,
    pub rules: [[u8; 32]; MAX_RULES],
    pub inline_assets: [[u8; 32]; MAX_INLINE_ASSETS],
    pub inline_count: u8,
    pub state_root: [u8; 32],
    pub nullifier_root: [u8; 32],
    pub answers: Vec<RuleAnswer>,
}

impl ProveRequest for CustomRingProofRequest {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        let tx_viewing_secret = self.tx_viewing_key.secret_bytes();
        let ephemeral_secret = self.ephemeral_key.secret_bytes();
        let auditor_key = self
            .auditor_key
            .to_p256()
            .map_err(|_| ClientError::Prover("invalid audit public key".to_string()))?;
        let auditor_pk = auditor_key.to_encoded_point(false);
        let json = CustomRingProofRequestJson {
            circuit_type: "custom-ring",
            variant: "transfer",
            public_input_hash: field_hex(&self.public_input_hash),
            private_tx_hash: field_hex(&self.private_tx_hash),
            tx_viewing_sk: SecretHex(tx_viewing_secret.as_slice()),
            eph_sk: SecretHex(ephemeral_secret.as_slice()),
            auditor_pk: bytes_to_hex(auditor_pk.as_bytes()),
            n_in: self.n_in,
            n_out: self.n_out,
            inputs: self.inputs.iter().map(opening_json).collect(),
            outputs: self.outputs.iter().map(opening_json).collect(),
            address_chain: field_hex(&self.address_chain),
            external_data_hash: field_hex(&self.external_data_hash),
            sources: self.sources.iter().map(source_json).collect(),
            policy_len: self.policy_len,
            rule_enc: self.rules.iter().map(field_hex).collect(),
            inline_assets: self.inline_assets.iter().map(field_hex).collect(),
            inline_count: self.inline_count,
            state_root: field_hex(&self.state_root),
            nullifier_root: field_hex(&self.nullifier_root),
            answers: self.answers.iter().map(answers_json).collect(),
        };
        serde_json::to_string(&json)
            .map(Zeroizing::new)
            .map_err(|_| ClientError::Prover("policy request serialization failed".to_string()))
    }

    fn delivery(&self) -> Delivery {
        Delivery::Queued
    }
}

fn opening_json(opening: &CustomRingOpening) -> CustomRingOpeningJson {
    CustomRingOpeningJson {
        domain: field_hex(&opening.domain),
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
struct CustomRingProofRequestJson<'a> {
    #[serde(rename = "circuitType")]
    circuit_type: &'static str,
    variant: &'static str,
    #[serde(rename = "publicInputHash")]
    public_input_hash: String,
    #[serde(rename = "privateTxHash")]
    private_tx_hash: String,
    #[serde(rename = "txViewingSk")]
    tx_viewing_sk: SecretHex<'a>,
    #[serde(rename = "ephSk")]
    eph_sk: SecretHex<'a>,
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
    sources: Vec<CustomRingSourceJson>,
    #[serde(rename = "policyLen")]
    policy_len: u8,
    #[serde(rename = "ruleEnc")]
    rule_enc: Vec<String>,
    #[serde(rename = "inlineAssets")]
    inline_assets: Vec<String>,
    #[serde(rename = "inlineCount")]
    inline_count: u8,
    #[serde(rename = "stateRoot")]
    state_root: String,
    #[serde(rename = "nullifierRoot")]
    nullifier_root: String,
    answers: Vec<RuleAnswerJson>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> CustomRingProofRequest {
        CustomRingProofRequest {
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
            sources: [SourceOwnerEntry::default(); MAX_SOURCES],
            policy_len: 1,
            rules: [[0u8; 32]; MAX_RULES],
            inline_assets: [[0u8; 32]; MAX_INLINE_ASSETS],
            inline_count: 0,
            state_root: [8u8; 32],
            nullifier_root: [9u8; 32],
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
                "auditorPk",
                "circuitType",
                "ephSk",
                "externalDataHash",
                "inlineAssets",
                "inlineCount",
                "inputs",
                "nIn",
                "nOut",
                "nullifierRoot",
                "outputs",
                "policyLen",
                "privateTxHash",
                "publicInputHash",
                "ruleEnc",
                "sources",
                "stateRoot",
                "txViewingSk",
                "variant",
            ]
        );
        assert_eq!(object["circuitType"], "custom-ring");
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
