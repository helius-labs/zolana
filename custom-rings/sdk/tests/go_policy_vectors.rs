//! Pins the record and policy hashing to the Go circuit. The values are the
//! fixture `prover/server/circuits/custom_ring/transfer/circuit_test.go` prints
//! under `PRINT_POLICY_VECTORS=1`, so a change on either side fails here.

use custom_ring_interface::{AuditPublicInput, CustomRingPublicInput};
use zolana_ring_policy::{
    record_nullifier, record_seed, Guard, Mode, Policy, PolicyMember, PolicyRecord, RecordKind,
    RecordState, RecordsOwner, Rule, Subject,
};

const RECORDS_PDA: [u8; 32] = [0x11; 32];
const RECIPIENT_TAG: [u8; 32] = [0xa1; 32];
const SENDER_TAG: [u8; 32] = [0xb2; 32];
const BLOCKED_TAG: [u8; 32] = [0xc3; 32];
const ASSET_MINT: [u8; 32] = [0xd4; 32];
/// The mint's `hash_bytes`, the value a UTXO carries as its asset field.
const ASSET_MEMBERS: &[[u8; 32]] = &[[
    0x14, 0xa6, 0xb5, 0x09, 0x2f, 0x94, 0x1b, 0xd4, 0x33, 0x6f, 0xe2, 0xa2, 0x5f, 0xc6, 0x17, 0xa9,
    0x51, 0x5b, 0x45, 0x7e, 0x02, 0x7e, 0x0c, 0xf5, 0xe4, 0x86, 0x7c, 0x08, 0x58, 0x85, 0x5e, 0xc1,
]];

const RECORDS_OWNER_HASH: &str = "1e99b255125d8e5d1a8ee78945c3197b227182301b2c5d263dd5410b5ff476be";
const POLICY_HASH: &str = "26e0fdcb7e8179a16c8e93ac37f839a34d6aa98dc6d4d318716b1e80efcbdd5e";

struct Vector {
    seed: &'static str,
    address: &'static str,
    data_hash: &'static str,
    utxo_hash: &'static str,
    nullifier: &'static str,
}

const ALLOW_PRESENT: Vector = Vector {
    seed: "1a226466656865c6abbc97ffe595edd254a69d89071e659fedc495d140b6f00e",
    address: "0ee2aa711dae06d975e5709ed68eafd75cd74070b75859093bb9becf3d2387b0",
    data_hash: "01b623e0a858d61692c7da1d75771d3bf368ef5f8647139f030ed3d281dc1c01",
    utxo_hash: "053cce0509ced4cd9c95c0f84c49b6fe40eeadf91d3166c8879db4c0b8df3c65",
    nullifier: "23ea6084012812863119d78a52a0ecdaa1431254e08d0f0d2c95a8accb9f1e68",
};

/// The frozen record was never created, so only its address is pinned.
const FROZEN_SEED: &str = "08e7b574f94761ce516d508af775433829e11b046e54e02912756d8fc0926db4";
const FROZEN_ADDRESS: &str = "1f951dd874310f3d77ede13b5c4a95f8eb7b9fc63db1642d85d6dae218a0d7dc";

const BLOCK_CLEARED: Vector = Vector {
    seed: "1f01f29f76e08896530395ef0169b0bcb96b52ce50f3f0350b791eb2f1356d18",
    address: "2f717b4319dbc570077080cfdf8ddaf15e2357bc6282adbd40940b7455869b7e",
    data_hash: "22c0474e22652fc298f31f82df3e64ea25390b75a37d303605b1d7bd037ef849",
    utxo_hash: "1a349272ecf58b247f3c461605e6b354ab316b6afb6e836160491cc0dad408d1",
    nullifier: "0210014fd4163aad3eae789aa5eceb789bcf928c85f23ad9ab897d38e13d70a1",
};

fn hex32(value: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(value, &mut bytes).expect("32-byte hex");
    bytes
}

fn owner() -> RecordsOwner {
    RecordsOwner::new(&RECORDS_PDA).expect("records owner")
}

fn check(vector: &Vector, kind: RecordKind, tag: [u8; 32], state: RecordState, version: u64) {
    let owner = owner();
    let member = PolicyMember::owner_tag(&tag).expect("member");
    assert_eq!(
        record_seed(kind, &member).expect("seed"),
        hex32(vector.seed),
        "seed"
    );
    let address = owner.address(kind, &member).expect("address");
    assert_eq!(address, hex32(vector.address), "address");

    let record = PolicyRecord {
        kind,
        member,
        state,
        version,
        payload_hash: [0u8; 32],
    };
    assert_eq!(
        record.data_hash(&address).expect("data hash"),
        hex32(vector.data_hash),
        "data hash"
    );
    let utxo_hash = record.utxo_hash(&owner, &address).expect("utxo hash");
    assert_eq!(utxo_hash, hex32(vector.utxo_hash), "utxo hash");
    assert_eq!(
        record_nullifier(&utxo_hash, &record.blinding()).expect("nullifier"),
        hex32(vector.nullifier),
        "nullifier"
    );
}

#[test]
fn record_hashing_matches_the_go_fixture() {
    assert_eq!(owner().owner_hash, hex32(RECORDS_OWNER_HASH));
    check(
        &ALLOW_PRESENT,
        RecordKind::Allow,
        RECIPIENT_TAG,
        RecordState::Active,
        0,
    );
    let sender = PolicyMember::owner_tag(&SENDER_TAG).expect("member");
    assert_eq!(
        record_seed(RecordKind::Frozen, &sender).expect("seed"),
        hex32(FROZEN_SEED)
    );
    assert_eq!(
        owner()
            .address(RecordKind::Frozen, &sender)
            .expect("address"),
        hex32(FROZEN_ADDRESS)
    );
    check(
        &BLOCK_CLEARED,
        RecordKind::Block,
        BLOCKED_TAG,
        RecordState::Cleared,
        1,
    );
}

#[test]
fn policy_hashing_matches_the_go_fixture() {
    let table = Policy::builder()
        .rule(Rule::require(Subject::OutputOwner, RecordKind::Allow))
        .rule(Rule::forbid(Subject::Sender, RecordKind::Frozen))
        .rule(Rule::allow_only_assets(ASSET_MEMBERS))
        .rule(Rule::require(Subject::OutputOwner, RecordKind::Approval).above(2000))
        .build();
    assert_eq!(
        table.hash(&owner().owner_hash).expect("policy hash"),
        hex32(POLICY_HASH)
    );
    assert!(matches!(table.rules()[3].guard, Guard::AboveAmount(2000)));
    assert!(matches!(table.rules()[1].mode, Mode::Absent));
}

#[test]
fn the_inline_asset_member_is_the_utxo_asset_field() {
    let member = PolicyMember::asset(&solana_address::Address::new_from_array(ASSET_MINT))
        .expect("asset member");
    assert_eq!(member.as_bytes(), &ASSET_MEMBERS[0]);
}

#[test]
fn the_public_input_chain_extends_the_audit_chain() {
    let audit = AuditPublicInput {
        private_tx_hash: &[1u8; 32],
        tx_viewing_pk: &[2u8; 33],
        auditor_pk: &[3u8; 33],
        eph_pk: &[4u8; 33],
        ciphertext: &[5u8; 32],
    };
    let elements = audit.elements().expect("elements");
    let policy = CustomRingPublicInput {
        audit,
        policy_hash: &hex32(POLICY_HASH),
        state_root: &[6u8; 32],
        nullifier_root: &[7u8; 32],
    };
    let chain = zolana_hasher::hash_chain::create_hash_chain_from_slice(&[
        elements[0],
        elements[1],
        elements[2],
        elements[3],
        elements[4],
        elements[5],
        elements[6],
        elements[7],
        hex32(POLICY_HASH),
        [6u8; 32],
        [7u8; 32],
    ])
    .expect("chain");
    assert_eq!(policy.hash().expect("policy input"), chain);
}

/// The program reads the policy config out of the prefix, so the builder must
/// place it there.
#[test]
fn the_policy_transact_carries_the_policy_config() {
    use custom_ring_sdk::CustomRing;
    let ring = CustomRing::new(solana_address::Address::new_from_array([3u8; 32]));
    let instruction = custom_ring_sdk::CustomRingTransact {
        ring,
        payer: solana_address::Address::new_from_array([1u8; 32]),
        input_tree: solana_address::Address::new_from_array([2u8; 32]),
        output_tree: solana_address::Address::new_from_array([2u8; 32]),
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        proof: custom_ring_sdk::CustomRingProof {
            proof_a: [0; 32],
            proof_b: [0; 64],
            proof_c: [0; 32],
            commitment: [0; 32],
            commitment_pok: [0; 32],
        },
        transact: transact_payload(),
        state_root_index: 0,
        nullifier_root_index: 0,
    }
    .instruction()
    .expect("build the policy transact");
    assert_eq!(instruction.accounts[0].pubkey, [1u8; 32].into());
    assert_eq!(instruction.accounts[1].pubkey, ring.config_pda());
    assert_eq!(instruction.accounts[2].pubkey, ring.policy_config_pda());
}

fn transact_payload() -> zolana_interface::instruction::instruction_data::transact::TransactIxData {
    use zolana_interface::instruction::instruction_data::transact::{CircuitId, TransactProof};
    zolana_interface::instruction::instruction_data::transact::TransactIxData {
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [0u8; 32],
        circuit: CircuitId::RingEddsa(1, 1, zolana_interface::N_PUBLIC_SLOTS as u8),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        proof: TransactProof::zeroed(),
        inputs: Vec::new(),
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs: Vec::new(),
        messages: Vec::new(),
    }
}
