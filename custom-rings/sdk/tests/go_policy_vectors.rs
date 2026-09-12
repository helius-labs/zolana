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
    Member, Mode, Rule, RuleTable, SourceMap, SpendCounters, SpendRecord, Subject, VelocityRow,
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
const POLICY_HASH: &str = "26a48b0231016dbbda9679b6bdbf5f0c83e9b57e3a80740a9d3f202a53020069";
const EMPTY_POLICY_HASH: &str = "2490087f66254407013a74d1326cffe8fbac9150f8d79fecff96832a5961bf58";
const ONE_RULE_POLICY_HASH: &str =
    "2f38f7031ce173b5ab9fd780b33ce9e7b7afb77d6600e61595c4d2d0304cfdfd";
const TWO_RULE_POLICY_HASH: &str =
    "19ac73c8d71f7b4801f39d4f8aaac7726355adeaaf67782d3209281801e60070";
const MIXED_RULE_POLICY_HASH: &str =
    "2c5dd56fe34bb7cba29dd66786ff0f2f111e97d6159fdf438a55f87313f52c09";
const PER_ASSET_POLICY_HASH: &str =
    "111b968e4313a7a6a3cfc0edf117bfde3fa2019f322c4cb00569aae57c4bc96c";
const VELOCITY_POLICY_HASH: &str =
    "1262836f44e627c676adb7ccd127c3a6a9f5ce27cba845d3d2a312fe010f2f09";
const TRANSFER_CAP_POLICY_HASH: &str =
    "23f6ecd26d9b5cd18c6b5ed303b9de7dfd70aa2412409c1f2403d3d096f23f8c";
/// The Go velocity fixture, version four inside window three spent into version five.
const SPEND_ADDRESS: &str = "0a01f0d4758639415a4c9c37e42d1878ea52f3f7e3821aed313835aec0850586";
const SPEND_COMMITMENT: &str = "2c8f5bde77147b8f6f9bd1e5edb381e8b14e39a117d1a8f94e8d58335e4e6c76";
const SPEND_DATA_HASH: &str = "2f0e7fc685bb0fdd86c6b1b4b75b9e18ec84dae130f3b5cdba0f12ec987f6de3";
const SPEND_UTXO_HASH: &str = "05e7e17a7845a03bdac567ab45ebe5f11814cd25c24bbd5a3d0ac651c1bdb0fc";
const SPEND_NEXT_COMMITMENT: &str =
    "05d117786af1550b31f6b0a83d76baffd51c2e6f73428c747b2269de4f7bf769";
const SPEND_NEXT_DATA_HASH: &str =
    "0f43075f27ce364f00f1d80fc51cfa03e41270edea2e3921f2d9902317cf3878";
const ZERO_COUNTERS_COMMITMENT: &str =
    "03bcb66825613582f9362a608fd94f6c4be191680bca9f8e75b1fee93268e1df";
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
fn velocity_rows_hash_to_the_go_fixture() {
    let table = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
        .window_slots(216_000)
        .velocity(&[VelocityRow {
            asset: ASSET_MEMBERS[0],
            cap: 5000,
            cosign_above: 600,
        }])
        .build();
    let map = SourceMap::new(&[(ListId::Allow, owner().owner_hash)]).expect("one source");
    assert_eq!(
        table.hash(&map).expect("velocity hash"),
        hex32(VELOCITY_POLICY_HASH)
    );
}

#[test]
fn transfer_cap_rows_hash_to_the_go_fixture() {
    let table = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
        .velocity(&[VelocityRow {
            asset: ASSET_MEMBERS[0],
            cap: 5000,
            cosign_above: 600,
        }])
        .build();
    let map = SourceMap::new(&[(ListId::Allow, owner().owner_hash)]).expect("one source");
    assert_eq!(
        table.hash(&map).expect("transfer cap hash"),
        hex32(TRANSFER_CAP_POLICY_HASH)
    );
}

fn field(value: u64) -> [u8; 32] {
    zolana_hasher::primitives::right_align(&value.to_be_bytes())
}

#[test]
fn spend_record_hashing_matches_the_go_fixture() {
    let owner = owner();
    let sender = Member::owner_tag(&SENDER_TAG).expect("member");
    let address = owner.spend_address(&sender, TREE_ID).expect("address");
    assert_eq!(address, hex32(SPEND_ADDRESS));

    let mut counters = SpendCounters::zero(&[ASSET_MEMBERS[0]]);
    counters.salt = field(0x5a17);
    counters.spent[0] = 700;
    assert_eq!(
        counters.commitment().expect("commitment"),
        hex32(SPEND_COMMITMENT)
    );
    let record = SpendRecord {
        member: sender,
        version: 4,
        window: 3,
        counters_commitment: counters.commitment().expect("commitment"),
        blinding: field(0x63),
    };
    assert_eq!(
        record.data_hash(&address).expect("data hash"),
        hex32(SPEND_DATA_HASH)
    );
    assert_eq!(
        record.utxo_hash(&owner, &address, TREE_ID).expect("leaf"),
        hex32(SPEND_UTXO_HASH)
    );

    let mut next = SpendCounters::zero(&[ASSET_MEMBERS[0]]);
    next.salt = field(0x5a18);
    next.spent[0] = 1700;
    assert_eq!(
        next.commitment().expect("commitment"),
        hex32(SPEND_NEXT_COMMITMENT)
    );
    let successor = SpendRecord {
        version: 5,
        counters_commitment: next.commitment().expect("commitment"),
        ..record
    };
    assert_eq!(
        successor.data_hash(&address).expect("data hash"),
        hex32(SPEND_NEXT_DATA_HASH)
    );
    assert_eq!(
        SpendCounters::zero(&[]).commitment().expect("zero"),
        hex32(ZERO_COUNTERS_COMMITMENT)
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
        namespace_owner_hash: owner().owner_hash,
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
        ring_id: &[8u8; 32],
        namespace_owner_hash: &[9u8; 32],
        window_index: 3,
        approval_required: true,
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
        [8u8; 32],
        [9u8; 32],
        field(3),
        field(1),
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
        cosigner: None,
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
        approval_required: false,
    }
    .instruction()
    .expect("build the policy transact");
    assert_eq!(instruction.accounts[0].pubkey, [1u8; 32].into());
    assert_eq!(instruction.accounts[1].pubkey, ring.config_pda());
    assert_eq!(instruction.accounts[2].pubkey, ring.cosigner_pda());
    assert_eq!(instruction.accounts[4].pubkey, ring.policy_config_pda());
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
