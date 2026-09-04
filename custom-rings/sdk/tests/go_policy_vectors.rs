//! Pins the entry and policy hashing to the Go circuit. The values are the
//! fixture `prover/server/circuits/custom_ring/policy/circuit_test.go` prints
//! under `PRINT_POLICY_VECTORS=1`, so a change on either side fails here.

use custom_ring_interface::{
    CustomRingBasePublicInput, CustomRingPolicyPublicInput, PolicyConfig, SourceSlot,
    N_SOURCE_SLOTS, POLICY_CONFIG,
};
use solana_address::Address;
use zolana_ring_policy::{
    entry_nullifier, entry_seed, EntryState, Guard, ListEntry, ListId, ListNamespace, ListSet,
    Member, Mode, Rule, RuleTable, SourceMap, Subject,
};

const RECORDS_PDA: [u8; 32] = [0x11; 32];
const CURATOR_PDA: [u8; 32] = [0x12; 32];
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
const CURATOR_OWNER_HASH: &str = "2719a8eec7b597c45bf36e95b85af000cbceef719715713fadec78fe81c88280";
const POLICY_HASH: &str = "243120278b6c15d93cd9b27feeb0586457cf41798c30c534da48f66e3fd76b69";
const EMPTY_POLICY_HASH: &str = "16fb955b8526ce537425c0fbef60b13ddb3ace36271b3d50ddaa8c16d65e1400";
const ONE_RULE_POLICY_HASH: &str =
    "226e9c2ba91e63d29176d27dd80711d501c284769b4d1a76c5c1676259bfd3ff";
const TWO_RULE_POLICY_HASH: &str =
    "0ab720d70035f79c4c91e8677e4753a855c3f7be0fcaf8f655883d258821189c";
const MIXED_RULE_POLICY_HASH: &str =
    "1d6806016526767233ca9acecf59629642e061ae50a0018192a78eb6617f46f8";
const PER_ASSET_POLICY_HASH: &str =
    "2903cae630b7cd871a2074e617e68dcd52fc866b28fab7c509033ef87357143d";
const PER_ASSET_RULES: RuleTable = RuleTable::builder()
    .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above_by_asset())
    .inline_assets(ASSET_MEMBERS)
    .inline_limits(&[123])
    .build();

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

/// The frozen entry was never created and its list reads a curator's
/// entries, so only its curator owned address is pinned.
const FROZEN_SEED: &str = "08e7b574f94761ce516d508af775433829e11b046e54e02912756d8fc0926db4";
const FROZEN_ADDRESS: &str = "061a65b955d92905ed3ac1ea36026f9171850fdcdb1ff5442fe90402da8b9f58";

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

fn owner() -> ListNamespace {
    ListNamespace::new(&RECORDS_PDA).expect("namespace owner")
}

fn curator() -> ListNamespace {
    ListNamespace::new(&CURATOR_PDA).expect("curator owner")
}

/// The fixture map, the frozen list reads the curator's entries.
fn fixture_sources() -> SourceMap {
    SourceMap::new(&[
        (ListId::Allow, owner().owner_hash),
        (ListId::Block, owner().owner_hash),
        (ListId::Frozen, curator().owner_hash),
        (ListId::Approval, owner().owner_hash),
    ])
    .expect("sources")
}

fn check(vector: &Vector, list_id: ListId, tag: [u8; 32], state: EntryState, version: u64) {
    let owner = owner();
    let member = Member::owner_tag(&tag).expect("member");
    assert_eq!(
        entry_seed(list_id, &member).expect("seed"),
        hex32(vector.seed),
        "seed"
    );
    let address = owner.address(list_id, &member).expect("address");
    assert_eq!(address, hex32(vector.address), "address");

    let entry = ListEntry {
        list_id,
        member,
        state,
        version,
        content_hash: [0u8; 32],
    };
    assert_eq!(
        entry.data_hash(&address).expect("data hash"),
        hex32(vector.data_hash),
        "data hash"
    );
    let utxo_hash = entry.utxo_hash(&owner, &address).expect("utxo hash");
    assert_eq!(utxo_hash, hex32(vector.utxo_hash), "utxo hash");
    assert_eq!(
        entry_nullifier(&utxo_hash, &entry.blinding()).expect("nullifier"),
        hex32(vector.nullifier),
        "nullifier"
    );
}

#[test]
fn record_hashing_matches_the_go_fixture() {
    assert_eq!(owner().owner_hash, hex32(RECORDS_OWNER_HASH));
    assert_eq!(curator().owner_hash, hex32(CURATOR_OWNER_HASH));
    check(
        &ALLOW_PRESENT,
        ListId::Allow,
        RECIPIENT_TAG,
        EntryState::Active,
        0,
    );
    let sender = Member::owner_tag(&SENDER_TAG).expect("member");
    assert_eq!(
        entry_seed(ListId::Frozen, &sender).expect("seed"),
        hex32(FROZEN_SEED)
    );
    assert_eq!(
        curator().address(ListId::Frozen, &sender).expect("address"),
        hex32(FROZEN_ADDRESS)
    );
    check(
        &BLOCK_CLEARED,
        ListId::Block,
        BLOCKED_TAG,
        EntryState::Cleared,
        1,
    );
}

#[test]
fn policy_hashing_matches_the_go_fixture() {
    let table = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
        .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
        .rule(Rule::allow_only_assets())
        .rule(Rule::require(Subject::OutputOwner, ListId::Approval).above(2000))
        .inline_assets(ASSET_MEMBERS)
        .build();
    assert_eq!(
        table.hash(&fixture_sources()).expect("policy hash"),
        hex32(POLICY_HASH)
    );
    assert!(matches!(table.rules()[3].guard, Guard::AboveAmount(2000)));
    assert!(matches!(table.rules()[1].primary_mode(), Mode::Absent));
}

/// The alt mask at byte 19 enters the packed row the hash chain folds.
#[test]
fn a_mixed_rule_hashes_to_the_go_fixture() {
    const MIXED: RuleTable = RuleTable::builder()
        .rule(Rule::any_of(
            Subject::OutputOwner,
            ListSet::single(ListId::Approval),
            ListSet::single(ListId::Block),
        ))
        .build();
    let map = SourceMap::new(&[
        (ListId::Block, owner().owner_hash),
        (ListId::Approval, owner().owner_hash),
    ])
    .expect("mixed sources");
    assert_eq!(
        MIXED.hash(&map).expect("mixed rule hash"),
        hex32(MIXED_RULE_POLICY_HASH)
    );
}

#[test]
fn source_map_hashing_matches_the_go_fixture() {
    const EMPTY: RuleTable = RuleTable::builder().build();
    assert_eq!(
        EMPTY.hash(&SourceMap::empty()).expect("empty hash"),
        hex32(EMPTY_POLICY_HASH)
    );
    const ONE_RULE: RuleTable = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
        .build();
    let one_map = SourceMap::new(&[(ListId::Allow, owner().owner_hash)]).expect("one source");
    assert_eq!(
        ONE_RULE.hash(&one_map).expect("one rule hash"),
        hex32(ONE_RULE_POLICY_HASH)
    );
    const TWO_RULES: RuleTable = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
        .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
        .build();
    let two_map = SourceMap::new(&[
        (ListId::Allow, owner().owner_hash),
        (ListId::Frozen, curator().owner_hash),
    ])
    .expect("two sources");
    assert_eq!(
        TWO_RULES.hash(&two_map).expect("two rule hash"),
        hex32(TWO_RULE_POLICY_HASH)
    );
}

#[test]
fn per_asset_limit_hashing_matches_the_go_fixture() {
    let map = SourceMap::new(&[(ListId::Allow, owner().owner_hash)]).expect("one source");
    assert_eq!(
        PER_ASSET_RULES.hash(&map).expect("per-asset hash"),
        hex32(PER_ASSET_POLICY_HASH)
    );
}

#[test]
fn policy_account_bytes_match_the_typescript_vector() {
    let sources = SourceMap::new(&[(ListId::Allow, owner().owner_hash)]).expect("sources");
    let mut slots = [SourceSlot {
        list_id: 0,
        namespace: Address::default(),
    }; N_SOURCE_SLOTS];
    slots[ListId::Allow.slot()] = SourceSlot {
        list_id: ListId::Allow as u8,
        namespace: Address::new_from_array(RECORDS_PDA),
    };
    let config = PolicyConfig {
        discriminator: POLICY_CONFIG,
        policy_hash: PER_ASSET_RULES.hash(&sources).expect("policy hash"),
        entries_tree: Address::new_from_array([0x22; 32]),
        namespace_bump: 254,
        bump: 253,
        sources: slots,
        rules: PER_ASSET_RULES.encode(),
        generation: 0x01020304u32.to_le_bytes(),
        generation_slot: 0x0102030405060708u64.to_le_bytes(),
    };
    let encoded: String = include_str!("fixtures/policy-config.hex")
        .split_whitespace()
        .collect();
    assert_eq!(hex::encode(bytemuck::bytes_of(&config)), encoded);
}

#[test]
fn the_inline_asset_member_is_the_utxo_asset_field() {
    let member =
        Member::asset(&solana_address::Address::new_from_array(ASSET_MINT)).expect("asset member");
    assert_eq!(member.as_bytes(), &ASSET_MEMBERS[0]);
}

#[test]
fn the_public_input_chain_extends_the_audit_chain() {
    let audit = CustomRingBasePublicInput {
        private_tx_hash: &[1u8; 32],
        tx_viewing_pk: &[2u8; 33],
        auditor_pk: &[3u8; 33],
        eph_pk: &[4u8; 33],
        ciphertext: &[5u8; 32],
    };
    let elements = audit.elements().expect("elements");
    let policy = CustomRingPolicyPublicInput {
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
        entries_tree: Some(solana_address::Address::new_from_array([4u8; 32])),
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
