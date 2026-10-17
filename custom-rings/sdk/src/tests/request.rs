use custom_ring_interface::{MAX_RING_DEPOSIT_AUDIT_SLOTS, MEMBER_REGISTRY_HEIGHT};
use serde_json::Value;
use solana_address::Address;
use zeroize::Zeroizing;
use zolana_client::{
    prover::indexed::{IndexedDepositRequest, IndexedRegistry},
    ProofInputUtxo, ProveRequest,
};
use zolana_interface::tree_slot::tree_id_field;
use zolana_ring_policy::{MAX_OUTFLOW_LIMITS, MAX_RULES, MAX_SOURCES};

use super::audit::{encrypted, private_tx_hash, tree, witness, REGISTRY_ROOT};
use crate::{
    golden_tests::{auditor, EPH_SK},
    prover::{RingCircuit, RingRequest},
    request::{DepositBody, PolicyBody, RecordWitness, SubjectWitness},
    witness::CustomRingWitness,
};

fn hex(value: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(value))
}

fn body(witness: CustomRingWitness) -> PolicyBody {
    encrypted(vec![ProofInputUtxo::default()])
        .pending
        .finish(private_tx_hash(), Box::new(witness), &[4; 32])
        .unwrap()
        .body
}

fn json(body: &PolicyBody) -> Value {
    serde_json::from_str(&RingRequest(body).body().unwrap()).unwrap()
}

fn sorted_keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
    keys.sort_unstable();
    keys
}

fn subject(present: bool) -> SubjectWitness {
    SubjectWitness {
        present,
        record: RecordWitness {
            next: [15; 32],
            lists: 5,
            escrow_key: [16; 32],
            index: 3,
            path: vec![[17; 32]; MEMBER_REGISTRY_HEIGHT],
        },
        low_member: [18; 32],
        low_next: [19; 32],
        low_lists: 1,
        low_escrow: [20; 32],
    }
}

#[test]
fn the_policy_request_matches_the_server_wire_format() {
    let value = json(&body(witness()));
    assert_eq!(
        sorted_keys(&value),
        [
            "addressChain",
            "addressTreeId",
            "approvalRequired",
            "auditorPk",
            "circuitType",
            "ephSk",
            "foreignRoot",
            "foreignSubjects",
            "inlineAssets",
            "inlineCount",
            "inlineLimits",
            "inputs",
            "keyEscrow",
            "limitCount",
            "limits",
            "memberRegistryRoot",
            "nIn",
            "nOut",
            "namespaceOwnerHash",
            "outputs",
            "policyLen",
            "privateTxBlinding",
            "privateTxHash",
            "publicInputHash",
            "ringId",
            "ruleEnc",
            "salt",
            "sources",
            "subjects",
            "treeSlots",
            "txViewingSk",
        ]
    );
    assert_eq!(value["circuitType"], "custom-ring-policy");
    assert_eq!(value["ruleEnc"].as_array().unwrap().len(), MAX_RULES);
    assert_eq!(value["sources"].as_array().unwrap().len(), MAX_SOURCES);
    assert_eq!(sorted_keys(&value["sources"][0]), ["listId", "registry"]);
    assert_eq!(
        value["limits"].as_array().unwrap().len(),
        MAX_OUTFLOW_LIMITS
    );
    assert_eq!(
        sorted_keys(&value["limits"][0]),
        ["asset", "cap", "cosignAbove"]
    );
    assert_eq!(value["subjects"].as_array().unwrap().len(), 13);
    assert_eq!(value["foreignSubjects"].as_array().unwrap().len(), 13);
    assert!(value["subjects"]
        .as_array()
        .unwrap()
        .iter()
        .all(Value::is_null));
    assert_eq!(
        sorted_keys(&value["outputs"][0]),
        [
            "amount",
            "asset",
            "blinding",
            "ctHash",
            "dataHash",
            "domain",
            "nullifierPk",
            "ownerPkHash",
            "ringDataHash",
            "ringProgramId",
            "treeId",
        ]
    );
}

#[test]
fn every_field_element_is_canonical_hex() {
    let value = json(&body(witness()));
    for name in [
        "memberRegistryRoot",
        "foreignRoot",
        "addressChain",
        "privateTxBlinding",
    ] {
        let field = value[name].as_str().unwrap();
        assert_eq!(field.len(), 66, "{name}");
        assert!(field.starts_with("0x"));
    }
    assert_eq!(value["memberRegistryRoot"], hex(&REGISTRY_ROOT));
    assert_eq!(value["addressChain"], hex(&[0; 32]));
    assert_eq!(value["addressTreeId"], hex(&tree_id_field(0)));
}

#[test]
fn subjects_open_in_slot_order_with_integer_lists_and_indices() {
    let mut witness = witness();
    witness.trees = vec![tree(3, 8)];
    witness.address_tree_id = 3;
    witness.subjects[0] = Some(subject(true));
    witness.subjects[5] = Some(subject(false));
    witness.foreign_root = [21; 32];
    witness.foreign_subjects[5] = Some(subject(true));
    witness.outputs[0].ct_hash = [22; 32];
    let value = json(&body(witness));
    assert_eq!(value["keyEscrow"], true);
    assert_eq!(value["addressTreeId"], hex(&tree_id_field(3)));
    let slots = value["treeSlots"].as_array().unwrap();
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0]["id"], hex(&tree_id_field(3)));
    assert_eq!(slots[0]["utxoRoot"], hex(&[8; 32]));
    let present = &value["subjects"][0];
    assert_eq!(present["present"], true);
    assert_eq!(present["lists"], 5);
    assert_eq!(present["index"], 3);
    assert_eq!(
        present["path"].as_array().unwrap().len(),
        MEMBER_REGISTRY_HEIGHT
    );
    assert_eq!(present["escrowKey"], hex(&[16; 32]));
    assert_eq!(present["lowLists"], 1);
    assert_eq!(
        sorted_keys(present),
        [
            "escrowKey",
            "index",
            "lists",
            "lowEscrow",
            "lowLists",
            "lowMember",
            "lowNext",
            "next",
            "path",
            "present",
        ]
    );
    assert!(value["subjects"][1].is_null());
    assert_eq!(value["subjects"][5]["present"], false);
    assert_eq!(value["foreignRoot"], hex(&[21; 32]));
    assert_eq!(value["foreignSubjects"][5]["present"], true);
    assert_eq!(value["outputs"][0]["ctHash"], hex(&[22; 32]));
}

#[test]
fn escrow_off_binds_a_zero_root() {
    let witness = CustomRingWitness {
        key_escrow: false,
        member_registry_root: [0; 32],
        ..witness()
    };
    let value = json(&body(witness));
    assert_eq!(value["keyEscrow"], false);
    assert_eq!(value["memberRegistryRoot"], hex(&[0; 32]));
}

fn record() -> RecordWitness {
    RecordWitness {
        next: [5; 32],
        lists: 2,
        escrow_key: [6; 32],
        index: 3,
        path: vec![[7; 32]; MEMBER_REGISTRY_HEIGHT],
    }
}

fn deposit(member_registry_root: Option<[u8; 32]>) -> DepositBody {
    let mut owners = [[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
    owners[0][31] = 2;
    let mut members: [Option<RecordWitness>; MAX_RING_DEPOSIT_AUDIT_SLOTS] = Default::default();
    members[0] = member_registry_root.map(|_| record());
    let mut ct_hashes = [[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
    ct_hashes[0] = member_registry_root.map_or([0; 32], |_| [8; 32]);
    DepositBody {
        circuit_type: RingCircuit::Deposit,
        public_input_hash: [0; 32],
        context_hash: [1; 32],
        count: 1,
        anonymous: false,
        owner_pk_hashes: owners,
        owner_keys: None,
        nullifier_pks: owners,
        blindings: Zeroizing::new(owners),
        ct_hashes,
        members,
        ephemeral_sk: Zeroizing::new(EPH_SK),
        auditor_pk: auditor(),
        key_escrow: member_registry_root.is_some(),
        member_registry_root: member_registry_root.unwrap_or_default(),
    }
}

#[test]
fn the_deposit_request_uses_fixed_slots_and_canonical_names() {
    let body = deposit(Some([9; 32]));
    let json: Value = serde_json::from_str(&RingRequest(&body).body().unwrap()).unwrap();
    assert_eq!(json["circuitType"], "custom-ring-deposit");
    assert_eq!(json["count"], 1);
    assert_eq!(json["ownerPkHashes"].as_array().unwrap().len(), 8);
    assert_eq!(json["ownerPkHashes"][0], format!("0x{:064x}", 2));
    assert_eq!(json["nullifierPks"][0], format!("0x{:064x}", 2));
    assert_eq!(json["blindings"][7], format!("0x{:064x}", 0));
    assert_eq!(json["ctHashes"].as_array().unwrap().len(), 8);
    assert_eq!(json["ctHashes"][0], hex(&[8; 32]));
    assert_eq!(json["members"].as_array().unwrap().len(), 8);
    assert_eq!(json["members"][0]["index"], 3);
    assert_eq!(json["members"][0]["lists"], 2);
    assert_eq!(
        json["members"][0]["path"].as_array().unwrap().len(),
        MEMBER_REGISTRY_HEIGHT
    );
    assert_eq!(
        sorted_keys(&json["members"][0]),
        ["escrowKey", "index", "lists", "next", "path"]
    );
    assert!(json["members"][1].is_null());
    assert_eq!(json["keyEscrow"], true);
    assert_eq!(json["memberRegistryRoot"], hex(&[9; 32]));
    assert_eq!(json["auditorPk"].as_str().unwrap().len(), 66);
    assert_eq!(json["ephSk"], hex(&EPH_SK));
    assert!(json.get("anonymous").is_none() && json.get("ownerKeys").is_none());
}

/// Only an anonymous deposit names its mode and the owner keys it discloses.
#[test]
fn an_anonymous_deposit_sends_its_owner_keys() {
    let mut body = deposit(None);
    body.anonymous = true;
    body.owner_keys = Some([[4; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS]);
    let json: Value = serde_json::from_str(&RingRequest(&body).body().unwrap()).unwrap();
    assert_eq!(json["anonymous"], true);
    assert_eq!(json["ownerKeys"].as_array().unwrap().len(), 8);
    assert_eq!(json["ownerKeys"][7], hex(&[4; 32]));
}

#[test]
fn escrow_off_sends_a_zero_deposit_root() {
    let body = deposit(None);
    let json: Value = serde_json::from_str(&RingRequest(&body).body().unwrap()).unwrap();
    assert_eq!(json["keyEscrow"], false);
    assert_eq!(json["memberRegistryRoot"], hex(&[0; 32]));
    assert!(json["members"]
        .as_array()
        .unwrap()
        .iter()
        .all(Value::is_null));
}

#[test]
fn the_indexed_deposit_binds_the_registry_the_body_names() {
    let body = deposit(Some([9; 32]));
    let registry = IndexedRegistry {
        ring_program_id: Address::new_from_array([3; 32]),
        root: [9; 32],
        next_index: 2,
    };
    assert!(IndexedDepositRequest::new(&RingRequest(&body), registry.clone()).is_ok());
    for changed in [
        IndexedRegistry {
            root: [8; 32],
            ..registry.clone()
        },
        IndexedRegistry {
            next_index: 0,
            ..registry.clone()
        },
        IndexedRegistry {
            next_index: (1 << 20) + 1,
            ..registry.clone()
        },
    ] {
        assert!(IndexedDepositRequest::new(&RingRequest(&body), changed).is_err());
    }
    assert!(IndexedDepositRequest::new(&RingRequest(&deposit(None)), registry).is_err());
}

#[test]
fn every_circuit_names_its_pinned_proving_key() {
    for circuit in [
        RingCircuit::BaseConfidential,
        RingCircuit::Base,
        RingCircuit::Policy,
        RingCircuit::DelegatePolicy,
        RingCircuit::Deposit,
        RingCircuit::RegisterKey,
        RingCircuit::UpdateMembers,
    ] {
        let key = circuit.proving_key().unwrap();
        assert_eq!(
            key.name,
            format!("{}.key", circuit.circuit_type().replace('-', "_"))
        );
    }
}
