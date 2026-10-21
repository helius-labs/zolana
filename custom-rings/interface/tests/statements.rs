//! `test-vectors/ring-statements.json`, every ring statement's elements and its
//! public input `HashChain4(elements)`, read by the circuits and the program.

use custom_ring_interface::{
    stream::RingTag, AnonymousAudit, AnonymousAuditKey, AnonymousLayout, ApplyRecordsStatement,
    AuditHead, AuditKind, AuditLayout, AuditStatement, DeliveredLayout, DepositContext,
    DepositPublicInput, DisclosureLayout, PackedLayout, PolicyKey, PolicyStatement,
    RegisterKeyStatement, RingOutput, DEPOSIT_PUBLIC_INPUT_ELEMENTS,
};
use serde::{Deserialize, Serialize};
use zolana_hasher::primitives::{hash_bytes, solana_owner_identity};

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/ring-statements.json"
);
/// `q - 1200`, the amount field of a 1200 withdrawal.
const WITHDRAWAL_1200: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffb51";

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct StatementVectors {
    description: String,
    audit: Vec<AuditCase>,
    policy: Vec<PolicyCase>,
    apply_records: ApplyCase,
    register_key: RegisterKeyCase,
    deposit: DepositCase,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct AuditCase {
    /// `packed`, `delivered` or `anonymous`.
    kind: String,
    first_nullifier: String,
    ring_id: String,
    tx_viewing_u: String,
    auditor_pubkey: String,
    eph_u: String,
    sealed: String,
    salt: String,
    /// `exits | key_escrow << 1 | data_free << 2 | full_openings << 3`.
    layout: u8,
    outputs: Vec<OutputCase>,
    disclosure: Vec<String>,
    private_tx_hash: Option<String>,
    epoch: Option<u64>,
    first_contact_root: Option<String>,
    sender_commitment: Option<String>,
    elements: Vec<String>,
    public_input_hash: String,
}

/// The values of one published slot a statement reads.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct OutputCase {
    /// `packed`, `delivered`, `anonymous` or `exit`.
    kind: String,
    hash: String,
    u: Option<String>,
    tag: Option<String>,
    body: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct PolicyCase {
    /// `member` or `delegate`.
    key: String,
    anonymous: Option<bool>,
    private_tx_hash: String,
    policy_hash: String,
    ring_id: String,
    approval_required: bool,
    key_escrow: bool,
    own_root: String,
    curator_root: String,
    sender: String,
    public_assets: Vec<String>,
    public_amounts: Vec<String>,
    elements: Vec<String>,
    public_input_hash: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct ApplyCase {
    old_root: String,
    new_root: String,
    old_next_index: u32,
    new_next_index: u32,
    chain_start: String,
    chain_end: String,
    count: u64,
    elements: Vec<String>,
    public_input_hash: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct RegisterKeyCase {
    member: String,
    nullifier_pk: String,
    auditor_pubkey: String,
    eph_u: String,
    ciphertext: String,
    elements: Vec<String>,
    public_input_hash: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct DepositCase {
    program_id: String,
    tree: String,
    spp_data: String,
    context_hash: String,
    anonymous: bool,
    owner_utxo_hashes: Vec<String>,
    ciphertexts: Vec<String>,
    auditor_pubkey: String,
    eph_pk: String,
    member_registry_root: Option<String>,
    elements: Vec<String>,
    public_input_hash: String,
}

fn field(seed: u8) -> [u8; 32] {
    let mut value = [seed; 32];
    value[0] = 0x1e;
    value
}

fn tagged(seed: u8) -> [u8; 33] {
    let mut key = [seed; 33];
    key[0] = 4;
    key
}

fn hexes(values: &[[u8; 32]]) -> Vec<String> {
    values.iter().map(hex::encode).collect()
}

struct Values {
    fields: Vec<[u8; 32]>,
    keys: Vec<[u8; 32]>,
    bodies: [[u8; 40]; 8],
    tags: [[u8; 31]; 8],
    auditor_pubkey: [u8; 33],
    ring_id: [u8; 32],
    salt: [u8; 16],
}

impl Values {
    fn new() -> Self {
        Self {
            fields: (0..80).map(field).collect(),
            keys: (0..16).map(|seed| [0x60 + seed; 32]).collect(),
            bodies: core::array::from_fn(|slot| [0x90 + slot as u8; 40]),
            tags: core::array::from_fn(|slot| [0xb0 + slot as u8; 31]),
            auditor_pubkey: tagged(0xa1),
            ring_id: hash_bytes(&[0x77; 32]).unwrap(),
            salt: [0x5c; 16],
        }
    }

    fn disclosure(&self, layout: DisclosureLayout) -> &[[u8; 32]] {
        &self.fields[40..40 + layout.field_count()]
    }

    fn head(&self, layout: AuditLayout) -> AuditHead<'_> {
        AuditHead {
            first_nullifier: &self.fields[1],
            ring_id: &self.ring_id,
            tx_viewing_u: &self.keys[0],
            auditor_pubkey: &self.auditor_pubkey,
            eph_u: &self.keys[1],
            sealed: &self.keys[2],
            salt: &self.salt,
            layout,
        }
    }

    fn exit(&self, slot: usize) -> RingOutput<'_> {
        RingOutput::Exit {
            hash: &self.fields[20 + slot],
            owner_tag: &self.keys[8],
            payload: &[],
        }
    }

    fn packed_outputs(&self) -> Vec<RingOutput<'_>> {
        vec![
            RingOutput::Packed {
                hash: &self.fields[20],
                u: &self.keys[3],
                ciphertext: &[],
            },
            self.exit(1),
        ]
    }

    fn delivered_outputs(&self) -> Vec<RingOutput<'_>> {
        (0..8)
            .map(|slot| match slot {
                2 | 5 => self.exit(slot),
                _ => RingOutput::Delivered {
                    hash: &self.fields[20 + slot],
                    u: &self.keys[4 + slot % 4],
                    body: &self.bodies[slot],
                },
            })
            .collect()
    }

    fn anonymous_outputs(&self) -> Vec<RingOutput<'_>> {
        (0..4)
            .map(|slot| match slot {
                3 => self.exit(slot),
                _ => RingOutput::Anonymous {
                    hash: &self.fields[20 + slot],
                    tag: RingTag::from_bytes(self.tags[slot]),
                    body: &self.bodies[slot],
                },
            })
            .collect()
    }
}

fn audit_case(statement: &AuditStatement<'_>) -> AuditCase {
    let head = statement.head;
    let anonymous = match statement.kind {
        AuditKind::Anonymous(anonymous) => Some(anonymous),
        AuditKind::Packed | AuditKind::Delivered => None,
    };
    let kind = match statement.kind {
        AuditKind::Packed => "packed",
        AuditKind::Delivered => "delivered",
        AuditKind::Anonymous(_) => "anonymous",
    };
    AuditCase {
        kind: kind.to_string(),
        first_nullifier: hex::encode(head.first_nullifier),
        ring_id: hex::encode(head.ring_id),
        tx_viewing_u: hex::encode(head.tx_viewing_u),
        auditor_pubkey: hex::encode(head.auditor_pubkey),
        eph_u: hex::encode(head.eph_u),
        sealed: hex::encode(head.sealed),
        salt: hex::encode(head.salt),
        layout: head.layout.value(),
        outputs: statement.outputs.iter().map(output_case).collect(),
        disclosure: hexes(statement.disclosure),
        private_tx_hash: anonymous.map(|anonymous| hex::encode(anonymous.private_tx_hash)),
        epoch: anonymous.map(|anonymous| anonymous.epoch),
        first_contact_root: anonymous.map(|anonymous| hex::encode(anonymous.first_contact_root)),
        sender_commitment: anonymous.map(|anonymous| hex::encode(anonymous.sender_commitment)),
        elements: hexes(&statement.elements().unwrap()),
        public_input_hash: hex::encode(statement.hash().unwrap()),
    }
}

fn output_case(output: &RingOutput<'_>) -> OutputCase {
    let (kind, u, tag, body) = match output {
        RingOutput::Packed { u, .. } => ("packed", Some(*u), None, None),
        RingOutput::Delivered { u, body, .. } => ("delivered", Some(*u), None, Some(*body)),
        RingOutput::Anonymous { tag, body, .. } => ("anonymous", None, Some(*tag), Some(*body)),
        RingOutput::Exit { .. } => ("exit", None, None, None),
    };
    OutputCase {
        kind: kind.to_string(),
        hash: hex::encode(output.hash()),
        u: u.map(hex::encode),
        tag: tag.map(|tag| hex::encode(tag.as_bytes())),
        body: body.map(hex::encode),
    }
}

fn policy_case(statement: &PolicyStatement<'_>) -> PolicyCase {
    let (key, anonymous) = match statement.key {
        PolicyKey::Member { anonymous } => ("member", Some(anonymous)),
        PolicyKey::Delegate => ("delegate", None),
    };
    PolicyCase {
        key: key.to_string(),
        anonymous,
        private_tx_hash: hex::encode(statement.private_tx_hash),
        policy_hash: hex::encode(statement.policy_hash),
        ring_id: hex::encode(statement.ring_id),
        approval_required: statement.approval_required,
        key_escrow: statement.key_escrow,
        own_root: hex::encode(statement.own_root),
        curator_root: hex::encode(statement.curator_root),
        sender: hex::encode(statement.sender),
        public_assets: hexes(statement.public_assets),
        public_amounts: hexes(statement.public_amounts),
        elements: hexes(&statement.elements()),
        public_input_hash: hex::encode(statement.hash().unwrap()),
    }
}

fn compute_vectors() -> StatementVectors {
    let values = Values::new();
    let (packed, delivered, anonymous) = (
        values.packed_outputs(),
        values.delivered_outputs(),
        values.anonymous_outputs(),
    );
    let anonymous_tail = AuditKind::Anonymous(AnonymousAudit {
        private_tx_hash: &values.fields[3],
        epoch: 6_734,
        first_contact_root: &values.fields[4],
        sender_commitment: &values.fields[5],
    });
    let commitment = AnonymousLayout {
        key: AnonymousAuditKey::Commitment { class: 4 },
        inputs: 3,
        outputs: 4,
        exits: true,
    };
    let audit = [
        AuditStatement {
            head: values.head(AuditLayout {
                exits: true,
                key_escrow: true,
                data_free: true,
                full_openings: false,
            }),
            outputs: &packed,
            disclosure: values.disclosure(DisclosureLayout::Packed(PackedLayout {
                outputs: 2,
                exits: true,
                key_escrow: true,
                data_free: true,
            })),
            kind: AuditKind::Packed,
        },
        AuditStatement {
            head: values.head(AuditLayout {
                exits: true,
                ..AuditLayout::default()
            }),
            outputs: &delivered,
            disclosure: values.disclosure(DisclosureLayout::Delivered(DeliveredLayout {
                outputs: 8,
                exits: true,
                key_escrow: false,
            })),
            kind: AuditKind::Delivered,
        },
        AuditStatement {
            head: values.head(AuditLayout {
                exits: true,
                ..AuditLayout::default()
            }),
            outputs: &anonymous,
            disclosure: values.disclosure(DisclosureLayout::Anonymous(commitment)),
            kind: anonymous_tail,
        },
        AuditStatement {
            head: values.head(AuditLayout {
                exits: true,
                data_free: true,
                full_openings: true,
                ..AuditLayout::default()
            }),
            outputs: &anonymous,
            disclosure: values.disclosure(DisclosureLayout::Anonymous(AnonymousLayout {
                key: AnonymousAuditKey::Entry,
                ..commitment
            })),
            kind: anonymous_tail,
        },
    ];
    let assets = [values.fields[60], values.fields[61], [0; 32]];
    let mut withdrawal = [0u8; 32];
    hex::decode_to_slice(WITHDRAWAL_1200, &mut withdrawal).unwrap();
    let amounts = [right_aligned(500), withdrawal, [0; 32]];
    let owner_signer = solana_owner_identity(&[0x42; 32]).unwrap();
    let zero = [0u8; 32];
    let confidential = PolicyStatement {
        key: PolicyKey::Member { anonymous: false },
        private_tx_hash: &values.fields[3],
        policy_hash: &values.fields[6],
        ring_id: &values.ring_id,
        approval_required: true,
        key_escrow: false,
        own_root: &values.fields[7],
        curator_root: &values.fields[8],
        sender: &owner_signer,
        public_assets: &assets,
        public_amounts: &amounts,
    };
    let anonymous_policy = PolicyStatement {
        key: PolicyKey::Member { anonymous: true },
        approval_required: false,
        sender: &values.fields[5],
        ..confidential
    };
    let delegate = PolicyStatement {
        key: PolicyKey::Delegate,
        approval_required: false,
        key_escrow: true,
        curator_root: &zero,
        sender: &zero,
        ..confidential
    };
    let apply = ApplyRecordsStatement {
        old_root: values.fields[9],
        new_root: values.fields[10],
        old_next_index: 5,
        new_next_index: 17,
        chain_start: values.fields[11],
        chain_end: values.fields[12],
        count: 16,
    };
    let register = RegisterKeyStatement {
        member: &owner_signer,
        nullifier_pk: &values.fields[13],
        auditor_pubkey: &values.auditor_pubkey,
        eph_u: &values.keys[9],
        ciphertext: &values.keys[10],
    };
    let program_id = [0x77; 32];
    let tree = [0x55; 32];
    let spp_data: Vec<u8> = (0..75u8).map(|byte| byte ^ 0x3c).collect();
    let context_hash = DepositContext {
        program_id: &program_id,
        tree: &tree,
        spp_data: &spp_data,
    }
    .hash()
    .unwrap();
    let owners = [values.fields[14], values.fields[15]];
    let ciphertexts = [[0x21; 96], [0x22; 96]];
    let eph_pk = tagged(0xa2);
    let deposit = DepositPublicInput {
        context_hash: &context_hash,
        anonymous: false,
        owner_utxo_hashes: &owners,
        ciphertexts: &ciphertexts,
        auditor_pk: &values.auditor_pubkey,
        eph_pk: &eph_pk,
        member_registry_root: Some(&values.fields[16]),
    };
    StatementVectors {
        description: "Every ring statement and its public input HashChain4(elements). Audit \
                      heads are [CRAU, n0, ring_id, pack_be(0x04 || tx_u), \
                      pack_be(auditor_pubkey), pack_be(0x04 || eph_u), hash_bytes(sealed), \
                      salt, layout] with the frame's random salt and layout = exits | key_escrow << 1 \
                      | data_free << 2 | full_openings << 3, the tails chain the published output \
                      hashes, the delivered and \
                      anonymous body hashes (zero for an exit), the disclosure fields, \
                      pack_be(u) per delivered slot and the 0x00 || tag field per anonymous \
                      slot. Each disclosure holds the field count of its layout, packed with 2 \
                      outputs, delivered with 8, anonymous of commitment class 4 and of the entry \
                      key with 3 inputs and 4 outputs. The deposit statement is HashChain(elements) \
                      over CRDP, the context hash of the program id, tree and SPP data, the \
                      count, the anonymous flag, each owner hash with its capsule ciphertext hash \
                      zero padded to 8 slots, both tagged keys packed, the registry flag and \
                      root. Produced by custom-rings/interface/tests/statements.rs."
            .to_string(),
        audit: audit.iter().map(audit_case).collect(),
        policy: [confidential, anonymous_policy, delegate]
            .iter()
            .map(policy_case)
            .collect(),
        apply_records: ApplyCase {
            old_root: hex::encode(apply.old_root),
            new_root: hex::encode(apply.new_root),
            old_next_index: apply.old_next_index,
            new_next_index: apply.new_next_index,
            chain_start: hex::encode(apply.chain_start),
            chain_end: hex::encode(apply.chain_end),
            count: apply.count,
            elements: hexes(&apply.elements()),
            public_input_hash: hex::encode(apply.hash().unwrap()),
        },
        register_key: RegisterKeyCase {
            member: hex::encode(register.member),
            nullifier_pk: hex::encode(register.nullifier_pk),
            auditor_pubkey: hex::encode(register.auditor_pubkey),
            eph_u: hex::encode(register.eph_u),
            ciphertext: hex::encode(register.ciphertext),
            elements: hexes(&register.elements().unwrap()),
            public_input_hash: hex::encode(register.hash().unwrap()),
        },
        deposit: DepositCase {
            program_id: hex::encode(program_id),
            tree: hex::encode(tree),
            spp_data: hex::encode(&spp_data),
            context_hash: hex::encode(context_hash),
            anonymous: deposit.anonymous,
            owner_utxo_hashes: hexes(&owners),
            ciphertexts: ciphertexts.iter().map(hex::encode).collect(),
            auditor_pubkey: hex::encode(deposit.auditor_pk),
            eph_pk: hex::encode(deposit.eph_pk),
            member_registry_root: deposit.member_registry_root.map(hex::encode),
            elements: hexes(&deposit.elements().unwrap()),
            public_input_hash: hex::encode(deposit.hash().unwrap()),
        },
    }
}

fn right_aligned(amount: u64) -> [u8; 32] {
    zolana_hasher::primitives::right_align(&amount.to_be_bytes())
}

#[test]
fn ring_statements_vector() {
    let committed: StatementVectors =
        serde_json::from_str(&std::fs::read_to_string(VECTORS).expect("vector file"))
            .expect("vector json");
    assert_eq!(committed, compute_vectors());
    let lengths: Vec<usize> = committed
        .audit
        .iter()
        .map(|case| case.elements.len())
        .collect();
    assert_eq!(lengths, [14, 16, 20, 20]);
    let policy: Vec<usize> = committed
        .policy
        .iter()
        .map(|case| case.elements.len())
        .collect();
    assert_eq!(policy, [16, 16, 15]);
    assert_eq!(
        committed.deposit.elements.len(),
        DEPOSIT_PUBLIC_INPUT_ELEMENTS
    );
}

#[test]
#[ignore = "rewrites test-vectors/ring-statements.json"]
fn write_ring_statements_vector() {
    let json = serde_json::to_string_pretty(&compute_vectors()).expect("json");
    std::fs::write(VECTORS, json + "\n").expect("write vector file");
}

#[test]
fn an_exit_slot_contributes_zero_bodies_keys_and_tags() {
    let values = Values::new();
    let exit = values.exit(0);
    assert_eq!(exit.body_hash(), Ok([0; 32]));
    assert_eq!(exit.recipient_key_fields(), [[0; 32]; 2]);
    assert_eq!(exit.tag_field(), [0; 32]);
    let anonymous = RingOutput::Anonymous {
        hash: &values.fields[0],
        tag: RingTag::from_bytes(values.tags[0]),
        body: &values.bodies[0],
    };
    let mut tag_field = [0u8; 32];
    tag_field[1..].copy_from_slice(&values.tags[0]);
    assert_eq!(anonymous.tag_field(), tag_field);
    assert_eq!(anonymous.body_hash(), hash_bytes(&values.bodies[0]));
}
