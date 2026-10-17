//! Pins the policy statement layout the Go circuit hashes and the account bytes the
//! TypeScript SDK decodes. The policy hash itself is cross-checked by the corpus in
//! `custom-rings/policy/tests/fixtures/policy-hash-corpus.json`.

use custom_ring_interface::{
    CustomRingBasePublicInput, CustomRingPolicyPublicInput, PolicyConfig, SourceSlot,
    N_SOURCE_SLOTS, POLICY_CONFIG,
};
use custom_ring_sdk::{CustomRing, PolicyReads, PolicyTreeContext, RegistryBinding};
use solana_address::Address;
use zolana_ring_policy::{
    registry_field, ListId, ListNamespace, Member, Rule, RuleTable, SourceMap, Subject,
};

const RECORDS_PDA: [u8; 32] = [0x11; 32];
const CURATOR_REGISTRY: [u8; 32] = [0x12; 32];
const ASSET_MINT: [u8; 32] = [0xd4; 32];
/// The address tree id the statement hashes under.
const TREE_ID: u16 = 7;
/// The mint's `hash_bytes`, the value a UTXO carries as its asset field.
const ASSET_MEMBERS: &[[u8; 32]] = &[[
    0x14, 0xa6, 0xb5, 0x09, 0x2f, 0x94, 0x1b, 0xd4, 0x33, 0x6f, 0xe2, 0xa2, 0x5f, 0xc6, 0x17, 0xa9,
    0x51, 0x5b, 0x45, 0x7e, 0x02, 0x7e, 0x0c, 0xf5, 0xe4, 0x86, 0x7c, 0x08, 0x58, 0x85, 0x5e, 0xc1,
]];

const PER_ASSET_RULES: RuleTable = RuleTable::builder()
    .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above_by_asset())
    .inline_assets(ASSET_MEMBERS)
    .inline_limits(&[123])
    .build();

fn owner() -> ListNamespace {
    ListNamespace::new(&RECORDS_PDA).expect("namespace owner")
}

fn field(value: u64) -> [u8; 32] {
    zolana_hasher::primitives::right_align(&value.to_be_bytes())
}

/// The stored slot carries the curator's registry address, the hash its field.
#[test]
fn a_curator_slot_hashes_the_registry_address_as_a_field() {
    let mut slots = [SourceSlot {
        list_id: 0,
        registry: Address::default(),
    }; N_SOURCE_SLOTS];
    slots[ListId::Allow.slot()] = SourceSlot {
        list_id: ListId::Allow as u8,
        registry: Address::new_from_array(CURATOR_REGISTRY),
    };
    let field = slots[ListId::Allow.slot()].policy_source().expect("field");
    assert_eq!(field.list_id, ListId::Allow as u8);
    assert_eq!(field.registry, registry_field(&CURATOR_REGISTRY).unwrap());
    assert_eq!(
        slots[ListId::Block.slot()]
            .policy_source()
            .expect("field")
            .registry,
        [0; 32]
    );
    let config = PolicyConfig {
        discriminator: POLICY_CONFIG,
        policy_hash: [0; 32],
        address_tree: Address::new_from_array([0x22; 32]),
        address_tree_id: TREE_ID.to_le_bytes(),
        namespace_bump: 254,
        bump: 253,
        namespace_owner_hash: owner().owner_hash,
        sources: slots,
        rules: RuleTable::builder()
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
            .build()
            .encode(),
        generation: 1u32.to_le_bytes(),
        generation_slot: 0u64.to_le_bytes(),
    };
    let map = config.source_map().expect("source map");
    assert_eq!(
        map.curator(),
        Some(registry_field(&CURATOR_REGISTRY).unwrap())
    );
    assert_eq!(
        config.curator(),
        Some(Address::new_from_array(CURATOR_REGISTRY))
    );
}

#[test]
fn policy_account_bytes_match_the_typescript_vector() {
    let sources = SourceMap::new(&[(ListId::Allow, [0; 32])]).expect("sources");
    let mut slots = [SourceSlot {
        list_id: 0,
        registry: Address::default(),
    }; N_SOURCE_SLOTS];
    slots[ListId::Allow.slot()] = SourceSlot {
        list_id: ListId::Allow as u8,
        registry: Address::default(),
    };
    let config = PolicyConfig {
        discriminator: POLICY_CONFIG,
        policy_hash: PER_ASSET_RULES.hash(&sources).expect("policy hash"),
        address_tree: Address::new_from_array([0x22; 32]),
        address_tree_id: 7u16.to_le_bytes(),
        namespace_bump: 254,
        bump: 253,
        namespace_owner_hash: owner().owner_hash,
        sources: slots,
        rules: PER_ASSET_RULES.encode(),
        generation: 0x01020304u32.to_le_bytes(),
        generation_slot: 0x0102030405060708u64.to_le_bytes(),
    };
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/policy-config.hex"
    );
    if std::env::var_os("WRITE_POLICY_CONFIG_HEX").is_some() {
        std::fs::write(path, hex::encode(bytemuck::bytes_of(&config)) + "\n").expect("write");
    }
    let encoded: String = std::fs::read_to_string(path)
        .expect("fixture")
        .split_whitespace()
        .collect();
    assert_eq!(
        hex::encode(bytemuck::bytes_of(&config)),
        encoded,
        "run with WRITE_POLICY_CONFIG_HEX=1"
    );
}

#[test]
fn the_inline_asset_member_is_the_utxo_asset_field() {
    let member =
        Member::asset(&solana_address::Address::new_from_array(ASSET_MINT)).expect("asset member");
    assert_eq!(member.as_bytes(), &ASSET_MEMBERS[0]);
}

/// Twenty-one elements, the audit prefix then the policy tail the Go circuit appends.
#[test]
fn the_public_input_chain_extends_the_audit_chain() {
    let audit = CustomRingBasePublicInput {
        private_tx_hash: &[1u8; 32],
        tx_viewing_pk: &[2u8; 33],
        auditor_pk: &[3u8; 33],
        eph_pk: &[4u8; 33],
        ciphertext: &[5u8; 32],
        output_hashes: &[[0u8; 32]; 4],
        salt: &[0u8; 16],
        disclosure: &[[0u8; 32]; custom_ring_interface::AUDIT_DISCLOSURE_FIELD_COUNT],
        anonymous: false,
    };
    let elements = audit.elements().expect("elements");
    let slots = [zolana_interface::tree_slot::TreeSlot::new(
        TREE_ID, [6u8; 32], [7u8; 32],
    )];
    let policy = CustomRingPolicyPublicInput {
        audit,
        policy_hash: &[10u8; 32],
        tree_slots: &slots,
        address_tree_id: TREE_ID,
        ring_id: &[8u8; 32],
        namespace_owner_hash: &[9u8; 32],
        approval_required: true,
        key_escrow: true,
        member_registry_root: &[11u8; 32],
        foreign_root: &[12u8; 32],
    };
    let mut expected = elements.to_vec();
    expected.extend_from_slice(&[
        [10u8; 32],
        zolana_interface::tree_slot::populated_tree_slots_hash_chain(&slots).expect("slots"),
        zolana_interface::tree_slot::tree_id_field(TREE_ID),
        [8u8; 32],
        [9u8; 32],
        field(1),
        field(1),
        [11u8; 32],
        [12u8; 32],
    ]);
    assert_eq!(expected.len(), 21);
    let chain = zolana_hasher::hash_chain::create_hash_chain_from_slice(&expected).expect("chain");
    assert_eq!(policy.hash().expect("policy input"), chain);
    let indexed = policy.indexed_inputs().expect("indexed inputs");
    assert_eq!(indexed.len(), 8);
    assert_eq!(
        indexed[0],
        zolana_hasher::hash_chain::create_hash_chain_from_slice(&expected[..13]).expect("fold")
    );
    assert_eq!(&indexed[1..], &expected[14..]);
}

/// The program reads the policy config out of the prefix, so the builder must
/// place it there.
#[test]
fn the_policy_transact_carries_the_policy_config() {
    let ring = CustomRing::new(solana_address::Address::new_from_array([3u8; 32]));
    let instruction = custom_ring_sdk::CustomRingTransact {
        cosigner: None,
        ring,
        payer: solana_address::Address::new_from_array([1u8; 32]),
        input_trees: vec![solana_address::Address::new_from_array([2u8; 32])],
        output_tree: solana_address::Address::new_from_array([2u8; 32]),
        policy: Some(PolicyReads {
            trees: vec![PolicyTreeContext {
                tree: solana_address::Address::new_from_array([4u8; 32]),
                context: zolana_interface::instruction::instruction_data::transact::TreeContext {
                    utxo_tree_root_index: 0,
                    nullifier_tree_root_index: 0,
                },
            }],
            registry: RegistryBinding::default(),
            foreign: None,
        }),
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        proof: custom_ring_sdk::CustomRingProof {
            groth16: custom_ring_interface::PlainGroth16Proof {
                proof_a: [0; 32],
                proof_b: [0; 64],
                proof_c: [0; 32],
            },
            commitment: [0; 32],
            commitment_pok: [0; 32],
        },
        transact: transact_payload(),
        approval_required: false,
    }
    .instruction()
    .expect("build the policy transact");
    assert_eq!(instruction.accounts[0].pubkey, ring.config_pda());
    assert_eq!(instruction.accounts[1].pubkey, ring.cosigner_pda());
    assert_eq!(instruction.accounts[3].pubkey, ring.policy_config_pda());
    assert_eq!(
        instruction.accounts[5].pubkey,
        ring.member_registry_root_pda()
    );
}

fn transact_payload() -> zolana_interface::instruction::instruction_data::transact::TransactIxData {
    use zolana_interface::instruction::instruction_data::transact::{
        CircuitId, TransactProof, TreeContext,
    };
    zolana_interface::instruction::instruction_data::transact::TransactIxData {
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [0u8; 32],
        circuit: CircuitId::ConfidentialRingEd25519(1, 1, zolana_interface::N_PUBLIC_SLOTS as u8),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        proof: TransactProof::zeroed(),
        inputs: Vec::new(),
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs: Vec::new(),
        messages: Vec::new(),
        tree_contexts: vec![TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        }],
    }
}

/// The small named policy vectors consumed by the TypeScript SDK.
#[test]
fn typescript_member_registry_policy_vectors() {
    use zolana_ring_policy::{ListSet, OutflowLimit};
    let allow = Rule::require(Subject::OutputOwner, ListId::Allow);
    let frozen = Rule::forbid(Subject::Sender, ListId::Frozen);
    let curator = registry_field(&CURATOR_REGISTRY).unwrap();
    let own = SourceMap::new(&[(ListId::Allow, [0; 32])]).unwrap();
    let mixed_sources =
        SourceMap::new(&[(ListId::Block, [0; 32]), (ListId::Approval, [0; 32])]).unwrap();
    let both = SourceMap::new(&[(ListId::Allow, [0; 32]), (ListId::Frozen, curator)]).unwrap();
    let four = SourceMap::new(&[
        (ListId::Allow, [0; 32]),
        (ListId::Block, [0; 32]),
        (ListId::Frozen, curator),
        (ListId::Approval, [0; 32]),
    ])
    .unwrap();
    let cases = [
        RuleTable::builder()
            .build()
            .hash(&SourceMap::new(&[]).unwrap())
            .unwrap(),
        RuleTable::builder().rule(allow).build().hash(&own).unwrap(),
        RuleTable::builder()
            .rule(allow)
            .rule(frozen)
            .build()
            .hash(&both)
            .unwrap(),
        RuleTable::builder()
            .rule(Rule::any_of(
                Subject::OutputOwner,
                ListSet::of(&[ListId::Approval]),
                ListSet::of(&[ListId::Block]),
            ))
            .build()
            .hash(&mixed_sources)
            .unwrap(),
        RuleTable::builder()
            .rule(allow)
            .rule(frozen)
            .rule(Rule::require(Subject::Asset, ListId::Allow))
            .rule(Rule::require(Subject::OutputOwner, ListId::Approval).above(2000))
            .build()
            .hash(&four)
            .unwrap(),
        PER_ASSET_RULES.hash(&own).unwrap(),
        RuleTable::builder()
            .rule(allow)
            .limits(&[OutflowLimit {
                asset: ASSET_MEMBERS[0],
                cap: 5000,
                cosign_above: 600,
            }])
            .build()
            .hash(&own)
            .unwrap(),
    ];
    let expected = [
        "1bf8b1374da19d08802d34a5d651751776d7e3b69a2aa844e3b7f93c80040622",
        "1c4fdae99597cb9cec253b622f3b988840c58713a682c4b6e8fe5b2f9ba5c07a",
        "0b596d952f79d4c04c609def6f2c9f0a0832620b334c54daded79115ebc7fc84",
        "300de33d9369363fb64b6a569465d1871eadfa32a8fa965738ce2cdd67127437",
        "0f58b60e0b035012dea442d57d379c4895fcd8f8ac44a8e4504db1f96bb1f451",
        "23187c7be3db2e0652d82eaa371419941256c92b0db3625e1ab62f8d9700ffcb",
        "031edd85abc0abefc06815a79a9325bc9cbd6461d1b77016fe96bccbc4a4a1f9",
    ];
    assert_eq!(cases.map(hex::encode), expected);
}
