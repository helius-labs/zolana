use custom_ring_interface::{KEY_REGISTRY_HEIGHT, MAX_RING_DEPOSIT_AUDIT_SLOTS};
use serde_json::Value;
use solana_address::Address;
use zeroize::Zeroizing;
use zolana_client::{
    prover::indexed::{IndexedDepositRequest, IndexedRegistry},
    ProofInputUtxo, ProveRequest, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use zolana_interface::tree_slot::tree_id_field;
use zolana_ring_policy::{ANSWER_SLOTS, MAX_OUTFLOW_LIMITS, MAX_RULES, MAX_SOURCES};

use super::audit::{encrypted, private_tx_hash, tree, witness};
use crate::{
    golden_tests::{auditor, EPH_SK},
    prover::{RingCircuit, RingRequest},
    request::{DepositBody, PolicyBody, RuleAnswer},
    witness::CustomRingWitness,
    RegistryKeyOpening,
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

fn answered() -> CustomRingWitness {
    CustomRingWitness {
        answers: vec![RuleAnswer::default(); ANSWER_SLOTS],
        ..witness()
    }
}

#[test]
fn the_policy_request_matches_the_server_wire_format() {
    let value = json(&body(answered()));
    assert_eq!(
        sorted_keys(&value),
        [
            "addressChain",
            "addressTreeId",
            "answers",
            "approvalRequired",
            "auditorPk",
            "circuitType",
            "ephSk",
            "inlineAssets",
            "inlineCount",
            "inlineLimits",
            "inputs",
            "keyEscrow",
            "keyRegistryRoot",
            "limitCount",
            "limits",
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
            "treeSlots",
            "txViewingSk",
        ]
    );
    assert_eq!(value["circuitType"], "custom-ring-policy");
    assert_eq!(value["ruleEnc"].as_array().unwrap().len(), MAX_RULES);
    assert_eq!(value["answers"].as_array().unwrap().len(), ANSWER_SLOTS);
    assert_eq!(value["sources"].as_array().unwrap().len(), MAX_SOURCES);
    assert_eq!(sorted_keys(&value["sources"][0]), ["listId", "ownerHash"]);
    assert_eq!(
        value["limits"].as_array().unwrap().len(),
        MAX_OUTFLOW_LIMITS
    );
    assert_eq!(
        sorted_keys(&value["limits"][0]),
        ["asset", "cap", "cosignAbove"]
    );
}

#[test]
fn every_field_element_is_canonical_hex() {
    let value = json(&body(answered()));
    let answer = &value["answers"][0];
    assert_eq!(
        answer["nfPathElements"].as_array().unwrap().len(),
        NULLIFIER_TREE_HEIGHT
    );
    assert_eq!(
        answer["statePathElements"].as_array().unwrap().len(),
        STATE_TREE_HEIGHT
    );
    // A disabled slot keeps its branch flags and list in range.
    assert_eq!(answer["enabled"], false);
    assert_eq!(answer["absentBranch"], 1);
    let hash = value["publicInputHash"].as_str().unwrap();
    assert_eq!(hash.len(), 66);
    assert!(hash.starts_with("0x") && hash.to_lowercase() == hash);
    assert_eq!(value["addressChain"], hex(&[0; 32]));
}

#[test]
fn escrowed_outputs_and_facts_name_their_key_and_tree_slot() {
    let mut witness = answered();
    witness.trees = vec![tree(3, 8), tree(9, 12)];
    witness.address_tree_id = 3;
    witness.outputs[0].key = Some(RegistryKeyOpening {
        next: [15; 32],
        ct_hash: [16; 32],
        index: 5,
        path: [[17; 32]; KEY_REGISTRY_HEIGHT],
    });
    witness.answers[0].tree_slot = 1;
    let value = json(&body(witness));
    assert_eq!(value["keyEscrow"], true);
    assert_eq!(value["keyRegistryRoot"], hex(&[12; 32]));
    assert_eq!(value["addressTreeId"], hex(&tree_id_field(3)));
    let slots = value["treeSlots"].as_array().unwrap();
    assert_eq!(slots.len(), 2);
    assert_eq!(slots[1]["id"], hex(&tree_id_field(9)));
    assert_eq!(slots[1]["utxoRoot"], hex(&[12; 32]));
    assert_eq!(slots[1]["nullifierRoot"], hex(&[13; 32]));
    let key = &value["outputs"][0]["key"];
    assert_eq!(key["ctHash"], hex(&[16; 32]));
    assert_eq!(key["index"], 5);
    assert_eq!(key["path"].as_array().unwrap().len(), KEY_REGISTRY_HEIGHT);
    assert!(value["outputs"][1].get("key").is_none());
    assert_eq!(value["answers"][0]["treeSlot"], 1);
    assert_eq!(value["answers"][1]["treeSlot"], 0);
}

#[test]
fn escrow_off_binds_a_zero_root() {
    let witness = CustomRingWitness {
        escrow: Default::default(),
        ..answered()
    };
    let value = json(&body(witness));
    assert_eq!(value["keyEscrow"], false);
    assert_eq!(value["keyRegistryRoot"], hex(&[0; 32]));
}

fn opening() -> RegistryKeyOpening {
    RegistryKeyOpening {
        next: [5; 32],
        ct_hash: [6; 32],
        index: 3,
        path: [[7; 32]; KEY_REGISTRY_HEIGHT],
    }
}

fn deposit(key_registry_root: Option<[u8; 32]>) -> DepositBody {
    let mut owners = [[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
    owners[0][31] = 2;
    let mut keys = [None; MAX_RING_DEPOSIT_AUDIT_SLOTS];
    keys[0] = key_registry_root.map(|_| opening());
    DepositBody {
        circuit_type: RingCircuit::Deposit,
        public_input_hash: [0; 32],
        context_hash: [1; 32],
        count: 1,
        owner_pk_hashes: owners,
        nullifier_pks: owners,
        blindings: Zeroizing::new(owners),
        keys,
        ephemeral_sk: Zeroizing::new(EPH_SK),
        auditor_pk: auditor(),
        key_escrow: key_registry_root.is_some(),
        key_registry_root: key_registry_root.unwrap_or_default(),
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
    assert_eq!(json["keys"].as_array().unwrap().len(), 8);
    assert_eq!(json["keys"][0]["index"], 3);
    assert_eq!(
        json["keys"][0]["path"].as_array().unwrap().len(),
        KEY_REGISTRY_HEIGHT
    );
    assert!(json["keys"][1].is_null());
    assert_eq!(json["keyEscrow"], true);
    assert_eq!(json["keyRegistryRoot"], hex(&[9; 32]));
    assert_eq!(json["auditorPk"].as_str().unwrap().len(), 66);
    assert_eq!(json["ephSk"], hex(&EPH_SK));
}

#[test]
fn escrow_off_sends_a_zero_deposit_root() {
    let body = deposit(None);
    let json: Value = serde_json::from_str(&RingRequest(&body).body().unwrap()).unwrap();
    assert_eq!(json["keyEscrow"], false);
    assert_eq!(json["keyRegistryRoot"], hex(&[0; 32]));
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
            next_index: (1 << 40) + 1,
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
        RingCircuit::Base,
        RingCircuit::Policy,
        RingCircuit::DelegatePolicy,
        RingCircuit::Deposit,
        RingCircuit::RegisterKey,
    ] {
        let key = circuit.proving_key().unwrap();
        assert_eq!(
            key.name,
            format!("{}.key", circuit.circuit_type().replace('-', "_"))
        );
    }
}
