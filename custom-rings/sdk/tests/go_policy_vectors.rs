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
/// The entries tree id the Go fixture hashes under.
const TREE_ID: u16 = 7;
/// The mint's `hash_bytes`, the value a UTXO carries as its asset field.
const ASSET_MEMBERS: &[[u8; 32]] = &[[
    0x14, 0xa6, 0xb5, 0x09, 0x2f, 0x94, 0x1b, 0xd4, 0x33, 0x6f, 0xe2, 0xa2, 0x5f, 0xc6, 0x17, 0xa9,
    0x51, 0x5b, 0x45, 0x7e, 0x02, 0x7e, 0x0c, 0xf5, 0xe4, 0x86, 0x7c, 0x08, 0x58, 0x85, 0x5e, 0xc1,
]];

const RECORDS_OWNER_HASH: &str = "2cb09cab7a637278cc7157bb6780f81e5abdcc5e001eddad5279891f03f05196";
const CURATOR_OWNER_HASH: &str = "13463a1c543bbe328fea6b0990a4014a613371d7390be03f7bc35cb4540753bb";
const POLICY_HASH: &str = "1be5d2fc725c11918d3ecbd5fcd0f5d7e78635dcffb0d7312246eaa380a51a7d";
const EMPTY_POLICY_HASH: &str = "16fb955b8526ce537425c0fbef60b13ddb3ace36271b3d50ddaa8c16d65e1400";
const ONE_RULE_POLICY_HASH: &str =
    "2ac1455d7a647806afa55bcdf3a99d4fffd378975d7268d3897f1f56ab14cf75";
const TWO_RULE_POLICY_HASH: &str =
    "1fd5912b36ce5c0bd249bf2f54020721f16eb70a52c3381ba8c71484e392f384";
const MIXED_RULE_POLICY_HASH: &str =
    "1a571ee1f11ce84b282e90fc7bf4358419c64e05a086d976b02b577e1ade2752";
const PER_ASSET_POLICY_HASH: &str =
    "0e70f40402bf8dd92ff898133027a599072c8b5e92a06aa15f8dfeebff212d1f";
const PER_ASSET_RULES: RuleTable = RuleTable::builder()
    .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above_by_asset())
    .inline_assets(ASSET_MEMBERS)
    .inline_limits(&[123])
    .build();

struct Vector {
    seed: &'static str,
    blinding: &'static str,
    address: &'static str,
    data_hash: &'static str,
    utxo_hash: &'static str,
    nullifier: &'static str,
}

const ALLOW_PRESENT: Vector = Vector {
    seed: "148b5ac42f444aa51bec37ae98ee6a26c6af968bf968e0eb50e749f3ef0eab04",
    blinding: "0000000000000000000000000000000000000000000000000000000000000001",
    address: "004fe1ffd9574dfaf0d8ab04f3db3602cc1fb8db8d10c8ebba62cf3923998abf",
    data_hash: "09c053bd16ca781e84e64bb353549e6dd9fbcc6e072e0a34e50c59fc3b6c9d2d",
    utxo_hash: "03409e610c10c6e82bead86f12d0f79872c66e8ca3a51d796de1726aeed137ab",
    nullifier: "0a4a91cd454e7f8acb5bc0df7bc826570caa1d22914a0cc8aa62db94a978af6d",
};

/// The frozen entry was never created and its list reads a curator's
/// entries, so only its curator owned address is pinned.
const FROZEN_SEED: &str = "1d07a2770e53955dd99bbf1a36348d8699fba111587451e3052d4fae3c23d5e6";
const FROZEN_ADDRESS: &str = "30036588ff59652a8d248e3c5927aaf96e08d59f40b3291c1eec8af8f7fd1687";

const BLOCK_CLEARED: Vector = Vector {
    seed: "071bb37c9c8db477e9c559891989aa7b774b7da82c0341bdd826d1f2d35430ba",
    blinding: "0000000000000000000000000000000000000000000000000000000000000003",
    address: "110828bc9145be37cd119865f66113d3858a8df6436fa6427eba07d152d7e654",
    data_hash: "145f4e2f25f4b57eefc76e760c8adfb06b48e7ea17f022c62c692d6530d9d9f3",
    utxo_hash: "0e5cc81efe63454ebd769c706d697141626499d60889f5207cd823a0dc23a461",
    nullifier: "03440de6febefc54740d90e51412d74ee76abd757d713ac3636d33e8b34068f2",
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
    let address = owner.address(list_id, &member, TREE_ID).expect("address");
    assert_eq!(address, hex32(vector.address), "address");

    let entry = ListEntry {
        list_id,
        member,
        state,
        version,
        content_hash: [0u8; 32],
        blinding: hex32(vector.blinding),
    };
    assert_eq!(
        entry.data_hash(&address).expect("data hash"),
        hex32(vector.data_hash),
        "data hash"
    );
    let utxo_hash = entry
        .utxo_hash(&owner, &address, TREE_ID)
        .expect("utxo hash");
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
        curator()
            .address(ListId::Frozen, &sender, TREE_ID)
            .expect("address"),
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
        entries_tree_id: 7u16.to_le_bytes(),
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
        entries_tree_id: TREE_ID,
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
        zolana_interface::tree_slot::tree_id_field(TREE_ID),
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
        utxo_tree_root_index: 0,
        nullifier_tree_root_index: 0,
    }
}
