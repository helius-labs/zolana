//! `test-vectors/ring-transact-expansion.json`, compact ring transact data and the SPP
//! data and external data hash the ring program forwards for it.

mod common;

use bytemuck::Zeroable;
use custom_ring_interface::{
    input_flag, shape_flag,
    stream::{RingTag, EPOCH_SLOTS, TAG_LEN},
    transact_flag, AnchorRoot, AnonymousAuditKey, AnonymousLayout, AnonymousProofData, AppliedAt,
    AuditBinding, AuditKind, CuratorRoot, CustomRingError, CustomRingProof, DeliveredLayout,
    DisclosureLayout, InputTrees, InstructionTag, MemberRegistry, PackedLayout, ParsedTransact,
    PlainGroth16Proof, PolicyBinding, PolicyProof, RailSigner, RingMode, RingOutput,
    RingProgramConfig, RingRail, RingTransactData, Settlement, SourceSlot, N_SOURCE_SLOTS,
    RING_PROGRAM_CONFIG,
};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_bn254::compression::prelude::alt_bn128_g2_compress_be;
use zolana_event::{
    confidential_encrypted_output_body, ring_anonymous_encrypted_output_body,
    ring_confidential_delivered_output_body, ring_confidential_packed_output_body,
    OutputDataEncoding, CONFIDENTIAL_DATA_FREE_BODY_LEN, CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
    RECIPIENT_KEY_LEN, RING_ANONYMOUS_ENCRYPTED_SCHEME_TAG, RING_PACKED_DATA_FREE_BODY_LEN,
};
use zolana_interface::{
    instruction::{InterfaceTransfer, OwnerTag, TransactIxData, TreeContext},
    shape::{Shape, SPP_SUPPORTED_SHAPES},
};
use zolana_ring_policy::{ListId, Member, OutflowLimit, RuleTable};

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/ring-transact-expansion.json"
);

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct ExpansionVectors {
    description: String,
    auditor_pubkey: String,
    co_signer: String,
    cases: Vec<Case>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Case {
    name: String,
    /// `confidential`, `anonymous` or `delegate`.
    rail: String,
    compact: String,
    /// Per public leg, the asset account then the user account.
    settlements: Vec<[String; 2]>,
    transact_ix_data: String,
    spp_instruction_data: String,
    external_data_hash: String,
}

/// Owned bytes every case borrows from.
struct Fixture {
    proofs: [CustomRingProof; 2],
    spp_proof: PlainGroth16Proof,
    fields: Vec<[u8; 32]>,
    bytes: [[u8; 32]; 24],
    bodies: [[u8; 40]; 8],
    tags: [[u8; TAG_LEN]; 4],
    ciphertext: Vec<u8>,
    data_free_ciphertext: Vec<u8>,
    payload: Vec<u8>,
    data_free_payload: Vec<u8>,
    salt: [u8; 16],
}

impl Fixture {
    fn new() -> Self {
        let proof = |seed: u8| CustomRingProof {
            groth16: PlainGroth16Proof {
                proof_a: [seed; 32],
                proof_b: [seed + 1; 64],
                proof_c: [seed + 2; 32],
            },
            commitment: [seed + 3; 32],
            commitment_pok: [seed + 4; 32],
        };
        Self {
            proofs: [proof(0x10), proof(0x20)],
            spp_proof: PlainGroth16Proof {
                proof_a: [0x31; 32],
                proof_b: alt_bn128_g2_compress_be(&common::spp_b()).unwrap(),
                proof_c: [0x32; 32],
            },
            fields: (0..64u8).map(field).collect(),
            bytes: core::array::from_fn(|i| [0x40 + i as u8; 32]),
            bodies: core::array::from_fn(|i| [0x80 + i as u8; 40]),
            tags: core::array::from_fn(|i| [0xa0 + i as u8; TAG_LEN]),
            ciphertext: (0..61).collect(),
            data_free_ciphertext: (0..(RING_PACKED_DATA_FREE_BODY_LEN - RECIPIENT_KEY_LEN) as u8)
                .map(|byte| byte ^ 0x33)
                .collect(),
            payload: (0..90).map(|byte: u8| byte ^ 0x5a).collect(),
            data_free_payload: (0..CONFIDENTIAL_DATA_FREE_BODY_LEN as u8)
                .map(|byte| byte ^ 0x66)
                .collect(),
            salt: [0x5c; 16],
        }
    }

    fn base(&self, rail: RingRail, n_in: u8, n_out: u8) -> RingTransactData<'_> {
        RingTransactData {
            rail,
            n_in,
            n_out,
            audit_proof: &self.proofs[0],
            policy: None,
            approval_required: false,
            previous_epoch: false,
            anchor: None,
            expiry_unix_ts: 1_800_000_000,
            tx_viewing_u: &self.bytes[0],
            salt: &self.salt,
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            data_free: false,
            key_escrow: false,
            full_openings: false,
            outputs: Vec::new(),
            eph_u: &self.bytes[1],
            sealed: &self.bytes[2],
            disclosure: &[],
            private_tx_hash: &self.fields[0],
            anonymous: None,
            spp_proof: &self.spp_proof,
            nullifiers: &self.fields[1..1 + usize::from(n_in)],
            input_trees: InputTrees::One(TreeContext {
                utxo_tree_root_index: 11,
                nullifier_tree_root_index: 12,
            }),
        }
    }

    fn packed<'a>(&'a self, slot: usize, ciphertext: &'a [u8]) -> RingOutput<'a> {
        RingOutput::Packed {
            hash: &self.fields[10 + slot],
            u: &self.bytes[3 + slot],
            ciphertext,
        }
    }

    fn exit<'a>(&'a self, slot: usize, payload: &'a [u8]) -> RingOutput<'a> {
        RingOutput::Exit {
            hash: &self.fields[10 + slot],
            owner_tag: &self.bytes[12 + slot],
            payload,
        }
    }

    fn with_disclosure<'a>(&'a self, mut data: RingTransactData<'a>) -> RingTransactData<'a> {
        let count = data.disclosure_layout().unwrap().field_count();
        data.disclosure = &self.fields[30..30 + count];
        data
    }

    /// A registry-mode policy ring's two-output transfer with an exit, both data hashes, two legs
    /// and two trees.
    fn confidential_packed(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Confidential, 2, 2);
        data.key_escrow = true;
        data.policy = Some(PolicyProof {
            proof: &self.proofs[1],
            own_root_index: 7,
            curator_root_index: Some(3),
            sender_commitment: None,
        });
        data.approval_required = true;
        data.interface_transfers = vec![
            InterfaceTransfer::SolWithdrawal { amount: 5_000 },
            InterfaceTransfer::SplDeposit {
                amount: 77,
                spl_interface_bump: 254,
            },
        ];
        data.data_hash = Some(&self.fields[2]);
        data.ring_data_hash = Some(&self.fields[3]);
        data.outputs = vec![
            self.packed(0, &self.ciphertext),
            self.exit(1, &self.payload),
        ];
        data.input_trees = InputTrees::Two {
            first: TreeContext {
                utxo_tree_root_index: 1,
                nullifier_tree_root_index: 2,
            },
            second: TreeContext {
                utxo_tree_root_index: 3,
                nullifier_tree_root_index: 4,
            },
            second_inputs: 0b10,
        };
        self.with_disclosure(data)
    }

    /// An audit-only ring's eight delivered slots, two of them data-free exits.
    fn confidential_delivered(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Confidential, 1, 8);
        data.data_free = true;
        data.outputs = (0..8)
            .map(|slot| match slot {
                3 | 6 => self.exit(slot, &self.data_free_payload),
                _ => self.delivered(slot),
            })
            .collect();
        self.with_disclosure(data)
    }

    /// An anonymous policy transfer from the previous epoch with a pair-anchored slot.
    fn anonymous(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Anonymous, 3, 4);
        data.policy = Some(PolicyProof {
            proof: &self.proofs[1],
            own_root_index: 31,
            curator_root_index: None,
            sender_commitment: Some(&self.fields[4]),
        });
        data.previous_epoch = true;
        data.anchor = Some(AnchorRoot {
            tree: 9,
            root_index: 300,
        });
        data.interface_transfers = vec![InterfaceTransfer::SolWithdrawal { amount: 9_999 }];
        data.data_free = true;
        data.outputs = (0..4)
            .map(|slot| match slot {
                2 => self.exit(slot, &self.data_free_payload),
                _ => self.tagged(slot),
            })
            .collect();
        data.anonymous = Some(AnonymousProofData {
            commitment: &self.bytes[20],
            commitment_pok: &self.bytes[21],
            default_owner_tag: Some(&self.bytes[22]),
        });
        self.with_disclosure(data)
    }

    /// An audit-only anonymous transfer spending a default-ring note under the entry key.
    fn anonymous_entry(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Anonymous, 2, 2);
        data.full_openings = true;
        data.outputs = vec![self.tagged(0), self.exit(1, &self.payload)];
        data.anonymous = Some(AnonymousProofData {
            commitment: &self.bytes[20],
            commitment_pok: &self.bytes[21],
            default_owner_tag: None,
        });
        self.with_disclosure(data)
    }

    /// A data-free delegate move, every output a packed ring output.
    fn delegate(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Delegate, 2, 2);
        data.key_escrow = true;
        data.policy = Some(self.delegate_policy());
        data.data_free = true;
        data.outputs = vec![
            self.packed(0, &self.data_free_ciphertext),
            self.packed(1, &self.data_free_ciphertext),
        ];
        self.with_disclosure(data)
    }

    /// A delegate move into eight delivered slots.
    fn delegate_delivered(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Delegate, 2, 8);
        data.key_escrow = true;
        data.policy = Some(self.delegate_policy());
        data.outputs = (0..8).map(|slot| self.delivered(slot)).collect();
        self.with_disclosure(data)
    }

    fn delegate_policy(&self) -> PolicyProof<'_> {
        PolicyProof {
            proof: &self.proofs[1],
            own_root_index: 0,
            curator_root_index: None,
            sender_commitment: None,
        }
    }

    fn delivered(&self, slot: usize) -> RingOutput<'_> {
        RingOutput::Delivered {
            hash: &self.fields[10 + slot],
            u: &self.bytes[3 + slot],
            body: &self.bodies[slot],
        }
    }

    fn tagged(&self, slot: usize) -> RingOutput<'_> {
        RingOutput::Anonymous {
            hash: &self.fields[10 + slot],
            tag: RingTag::from_bytes(self.tags[slot]),
            body: &self.bodies[slot],
        }
    }

    fn cases(&self) -> [(&'static str, RingTransactData<'_>); 6] {
        [
            ("confidential_packed_policy", self.confidential_packed()),
            (
                "confidential_delivered_audit_only",
                self.confidential_delivered(),
            ),
            ("anonymous_policy_previous_epoch_anchor", self.anonymous()),
            ("anonymous_entry_audit_only", self.anonymous_entry()),
            ("delegate_move", self.delegate()),
            ("delegate_delivered_move", self.delegate_delivered()),
        ]
    }
}

fn field(seed: u8) -> [u8; 32] {
    let mut value = [seed; 32];
    value[0] = 0x0f;
    value
}

fn config() -> RingProgramConfig {
    let mut config: RingProgramConfig = Zeroable::zeroed();
    config.discriminator = RING_PROGRAM_CONFIG;
    config.auditor_pubkey[0] = 4;
    config.auditor_pubkey[1..].copy_from_slice(&[0xa1; 32]);
    config.co_signer = Address::new_from_array([0xc5; 32]);
    config
}

fn settlements(legs: usize) -> Vec<[[u8; 32]; 2]> {
    (0..legs)
        .map(|leg| [[0xe0 + leg as u8; 32], [0xf0 + leg as u8; 32]])
        .collect()
}

fn compute_vectors() -> ExpansionVectors {
    let fixture = Fixture::new();
    let config = config();
    let cases = fixture
        .cases()
        .into_iter()
        .map(|(name, data)| {
            let legs = settlements(data.interface_transfers.len());
            let borrowed: Vec<Settlement<'_>> = legs
                .iter()
                .map(|[asset_account, user_account]| Settlement {
                    asset_account,
                    user_account,
                })
                .collect();
            Case {
                name: name.to_string(),
                rail: data.rail.to_string(),
                compact: hex::encode(data.encode().unwrap()),
                settlements: legs.iter().map(|leg| leg.map(hex::encode)).collect(),
                transact_ix_data: hex::encode(data.expand(&config).unwrap().serialize().unwrap()),
                spp_instruction_data: hex::encode(data.spp_instruction_data(&config).unwrap()),
                external_data_hash: hex::encode(
                    data.external_data_hash(&config, &borrowed).unwrap(),
                ),
            }
        })
        .collect();
    ExpansionVectors {
        description: "Compact ring transact data of each rail and what the ring program forwards \
                      for it, the SPP TransactIxData, the SPP instruction data (tag 19 or 21, the \
                      data, the configured co-signer on an anonymous ring) and the external data \
                      hash over the SPP tag, the data before private_tx_hash and two settlement \
                      accounts per leg. Byte 1 of the compact data indexes \
                      SPP_SUPPORTED_SHAPES below the default owner tag flag (bit 6) and the \
                      data-free flag (bit 7), under which packed ciphertexts take 49 bytes and \
                      exit payloads 83 bytes without a u16 prefix. Byte 2 is the input count \
                      below the key escrow flag (bit 6) and the anonymous entry key flag (bit \
                      7), the expiry is a u32, delivered and anonymous rails publish no output \
                      count, packed slots expand as scheme 11 and the random 16-byte salt follows \
                      the transaction viewing key. Produced by \
                      custom-rings/interface/tests/transact.rs."
            .to_string(),
        auditor_pubkey: hex::encode(config.auditor_pubkey),
        co_signer: hex::encode(config.co_signer.as_array()),
        cases,
    }
}

fn rail(name: &str) -> RingRail {
    [
        RingRail::Confidential,
        RingRail::Anonymous,
        RingRail::Delegate,
    ]
    .into_iter()
    .find(|rail| rail.to_string() == name)
    .unwrap_or_else(|| panic!("unknown rail {name}"))
}

#[test]
fn ring_transact_expansion_vector() {
    let committed: ExpansionVectors =
        serde_json::from_str(&std::fs::read_to_string(VECTORS).expect("vector file"))
            .expect("vector json");
    assert_eq!(committed, compute_vectors());
    let config = config();
    for case in &committed.cases {
        let compact = hex::decode(&case.compact).unwrap();
        let data = RingTransactData::parse(&compact, rail(&case.rail))
            .unwrap()
            .into_data();
        assert_eq!(data.encode().unwrap(), compact, "{}", case.name);
        let expanded = hex::decode(&case.transact_ix_data).unwrap();
        let spp = TransactIxData::deserialize(&expanded).unwrap();
        assert_eq!(spp, data.expand(&config).unwrap(), "{}", case.name);
        assert_eq!(spp.proof.b, common::spp_b());
        assert_eq!(&spp.salt, data.salt, "{}", case.name);
        assert_eq!(spp.messages[0].view_tag, config.auditor_pubkey[1..]);
        for (output, slot) in spp.outputs.iter().zip(&data.outputs) {
            let framed = output.data.as_deref().unwrap();
            let body = match slot {
                RingOutput::Packed { u, ciphertext, .. } => {
                    let body = ring_confidential_packed_output_body(framed).unwrap();
                    assert_eq!(body.key[0], 4, "{}", case.name);
                    assert_eq!(
                        (&body.key[1..], body.ciphertext),
                        (&u[..], *ciphertext),
                        "{}",
                        case.name
                    );
                    Some(body.ciphertext)
                }
                RingOutput::Delivered { .. } => {
                    ring_confidential_delivered_output_body(framed).map(|body| &body[..])
                }
                RingOutput::Anonymous { tag, .. } => {
                    assert_eq!(output.owner_tag, OwnerTag::Inline(tag.field()));
                    ring_anonymous_encrypted_output_body(framed)
                }
                RingOutput::Exit { .. } => confidential_encrypted_output_body(framed),
            };
            assert!(body.is_some(), "{} output framing", case.name);
        }
        let mut forwarded = vec![data.rail.spp_tag()];
        forwarded.extend(&expanded);
        if data.rail == RingRail::Anonymous {
            forwarded.extend(config.co_signer.as_array());
        }
        assert_eq!(hex::encode(forwarded), case.spp_instruction_data);
    }
}

#[test]
#[ignore = "rewrites test-vectors/ring-transact-expansion.json"]
fn write_ring_transact_expansion_vector() {
    let json = serde_json::to_string_pretty(&compute_vectors()).expect("json");
    std::fs::write(VECTORS, json + "\n").expect("write vector file");
}

#[test]
fn anonymous_and_exit_slots_keep_the_borsh_framing_at_exact_capacity() {
    let fixture = Fixture::new();
    let borsh_framing = |scheme: u8, payload: &[u8]| {
        borsh::to_vec(&OutputDataEncoding::Encrypted(
            [&[scheme][..], payload].concat(),
        ))
        .unwrap()
    };
    for (slot, scheme, payload) in [
        (
            fixture.tagged(0),
            RING_ANONYMOUS_ENCRYPTED_SCHEME_TAG,
            &fixture.bodies[0][..],
        ),
        (
            fixture.exit(1, &fixture.payload),
            CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
            &fixture.payload[..],
        ),
        (
            fixture.exit(2, &fixture.data_free_payload),
            CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
            &fixture.data_free_payload[..],
        ),
    ] {
        let data = slot.transact_output().data.unwrap();
        assert_eq!(data, borsh_framing(scheme, payload), "scheme {scheme}");
        assert_eq!(data.capacity(), data.len(), "scheme {scheme}");
    }
}

#[test]
fn the_counts_fix_every_length_and_trailing_bytes_are_refused() {
    let fixture = Fixture::new();
    for (name, data) in fixture.cases() {
        let mut compact = data.encode().unwrap();
        compact.push(0);
        assert_eq!(
            RingTransactData::parse(&compact, data.rail),
            Err(CustomRingError::RingTransactLength),
            "{name}"
        );
        compact.truncate(compact.len() - 2);
        assert_eq!(
            RingTransactData::parse(&compact, data.rail),
            Err(CustomRingError::RingTransactLength),
            "{name}"
        );
    }
}

#[test]
fn a_delivered_rail_publishes_every_output_slot() {
    let fixture = Fixture::new();
    let mut data = fixture.confidential_delivered();
    data.outputs.pop();
    assert_eq!(data.encode(), Err(CustomRingError::RingTransactLength));
}

fn shape_index(n_in: usize, n_out: usize) -> u8 {
    let shape = Shape::new(n_in, n_out);
    SPP_SUPPORTED_SHAPES
        .iter()
        .position(|supported| *supported == shape)
        .unwrap() as u8
}

#[test]
fn counts_outside_the_keyed_shapes_are_refused() {
    let fixture = Fixture::new();
    let packed = fixture.confidential_packed().encode().unwrap();
    let mut unindexed = packed.clone();
    unindexed[1] = SPP_SUPPORTED_SHAPES.len() as u8;
    assert_eq!(
        RingTransactData::parse(&unindexed, RingRail::Confidential),
        Err(CustomRingError::RingShapeUnkeyed)
    );
    let mut excess = packed;
    excess[2] = excess[2] & !0b0011_1111 | 3;
    assert_eq!(
        RingTransactData::parse(&excess, RingRail::Confidential),
        Err(CustomRingError::RingTransactLength)
    );
    let mut wide = fixture.anonymous().encode().unwrap();
    wide[1] = shape_index(2, 16) | (wide[1] & !0b0011_1111);
    assert_eq!(
        RingTransactData::parse(&wide, RingRail::Anonymous),
        Err(CustomRingError::RingShapeUnkeyed)
    );
}

#[test]
fn anonymous_header_flags_off_the_anonymous_rail_are_refused() {
    let fixture = Fixture::new();
    let mut entry = fixture.confidential_packed().encode().unwrap();
    entry[input_flag::BYTE] |= input_flag::FULL_OPENINGS;
    assert_eq!(
        RingTransactData::parse(&entry, RingRail::Confidential),
        Err(CustomRingError::FlagNotAllowed)
    );
    let mut owner_tag = fixture.confidential_packed().encode().unwrap();
    owner_tag[shape_flag::BYTE] |= shape_flag::DEFAULT_OWNER_TAG;
    assert_eq!(
        RingTransactData::parse(&owner_tag, RingRail::Confidential),
        Err(CustomRingError::FlagNotAllowed)
    );
}

#[test]
fn flags_the_rail_forbids_are_refused() {
    let fixture = Fixture::new();
    let mut anchored = fixture.confidential_delivered().encode().unwrap();
    anchored[transact_flag::BYTE] |= transact_flag::ANCHOR;
    assert_eq!(
        RingTransactData::parse(&anchored, RingRail::Confidential),
        Err(CustomRingError::FlagNotAllowed)
    );
    let mut curator = fixture.confidential_delivered().encode().unwrap();
    curator[transact_flag::BYTE] |= transact_flag::CURATOR;
    assert_eq!(
        RingTransactData::parse(&curator, RingRail::Confidential),
        Err(CustomRingError::FlagNotAllowed)
    );
    let mut exit = fixture.delegate();
    exit.rail = RingRail::Confidential;
    exit.outputs[1] = fixture.exit(1, &fixture.data_free_payload);
    let compact = fixture.with_disclosure(exit).encode().unwrap();
    assert_eq!(
        RingTransactData::parse(&compact, RingRail::Delegate),
        Err(CustomRingError::FlagNotAllowed)
    );
}

#[test]
fn a_data_free_packed_ciphertext_of_another_length_is_refused() {
    let fixture = Fixture::new();
    let mut data = fixture.delegate();
    data.outputs[1] = fixture.packed(1, &fixture.ciphertext);
    assert_eq!(data.encode(), Err(CustomRingError::DataFreeBodyLength));
}

#[test]
fn a_data_free_exit_payload_of_another_length_is_refused() {
    let fixture = Fixture::new();
    let mut data = fixture.confidential_delivered();
    data.outputs[3] = fixture.exit(3, &fixture.payload);
    assert_eq!(data.encode(), Err(CustomRingError::DataFreeBodyLength));
}

#[test]
fn the_data_free_flag_drops_the_body_prefixes_and_keeps_the_outputs() {
    let fixture = Fixture::new();
    let mut prefixed = fixture.delegate();
    prefixed.data_free = false;
    let prefixed = fixture.with_disclosure(prefixed);
    let data_free = fixture.delegate().encode().unwrap();
    assert_eq!(
        data_free[shape_flag::BYTE] & shape_flag::DATA_FREE,
        shape_flag::DATA_FREE
    );
    let parsed = |compact: &[u8]| {
        RingTransactData::parse(compact, RingRail::Delegate)
            .unwrap()
            .data()
            .expand(&config())
            .unwrap()
            .outputs
    };
    assert_eq!(parsed(&prefixed.encode().unwrap()), parsed(&data_free));
}

#[test]
fn bitmap_bits_past_the_count_are_refused() {
    let fixture = Fixture::new();
    let mut compact = fixture.confidential_packed().encode().unwrap();
    let tree_bitmap = compact.len() - 9;
    compact[tree_bitmap] |= 1 << 7;
    assert_eq!(
        RingTransactData::parse(&compact, RingRail::Confidential),
        Err(CustomRingError::InvalidInstructionData)
    );
}

#[test]
fn an_spp_point_off_the_curve_is_refused_at_expansion() {
    let fixture = Fixture::new();
    let off_curve = PlainGroth16Proof {
        proof_b: [0xff; 64],
        ..fixture.spp_proof
    };
    let mut data = fixture.delegate();
    data.spp_proof = &off_curve;
    let compact = data.encode().unwrap();
    let parsed = RingTransactData::parse(&compact, RingRail::Delegate).unwrap();
    assert_eq!(
        parsed.data().expand(&config()),
        Err(CustomRingError::InvalidSppProofPoint)
    );
}

#[test]
fn the_previous_epoch_flag_needs_an_epoch_before() {
    let fixture = Fixture::new();
    let data = fixture.anonymous();
    assert_eq!(
        data.epoch(EPOCH_SLOTS - 1),
        Err(CustomRingError::EpochUnderflow)
    );
    assert_eq!(data.epoch(2 * EPOCH_SLOTS), Ok(1));
}

#[test]
fn the_policy_proof_follows_the_registry() {
    let fixture = Fixture::new();
    let packed = fixture.confidential_packed();
    let mut registry = MemberRegistry::new(254, 0);
    assert_eq!(
        packed.check_policy(None),
        Err(CustomRingError::UnexpectedPolicyProof)
    );
    assert_eq!(
        packed.check_policy(Some(&registry)),
        Err(CustomRingError::FlagNotAllowed)
    );
    let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
    sources[0] = SourceSlot {
        list_id: ListId::Allow as u8,
        registry: Address::new_from_array([3; 32]),
    };
    registry.sources = sources;
    assert_eq!(
        packed.check_policy(Some(&registry)),
        Err(CustomRingError::UnexpectedApproval)
    );
    registry.rules = RuleTable::builder()
        .limits(&[
            OutflowLimit::of(&Member::asset(&Address::new_from_array([1; 32])).unwrap())
                .with_cap(10)
                .with_cosign_above(5),
        ])
        .build()
        .encode();
    assert_eq!(
        packed.check_policy(Some(&registry)),
        Err(CustomRingError::PolicyNotSet)
    );
    registry.policy_hash = [9; 32];
    for applied in 1..=7 {
        let at = AppliedAt {
            applied,
            slot: applied,
        };
        registry.push_root([applied as u8; 32], at);
    }
    assert_eq!(
        packed.check_policy(Some(&registry)),
        Ok(Some(PolicyBinding {
            proof: packed.policy.unwrap(),
            policy_hash: [9; 32],
            own_root: [7; 32],
            curator: Some(CuratorRoot {
                registry: Address::new_from_array([3; 32]),
                root_index: 3,
            }),
        }))
    );
    assert_eq!(
        fixture
            .confidential_delivered()
            .check_policy(Some(&registry)),
        Err(CustomRingError::MissingPolicyProof)
    );
    assert_eq!(
        fixture.confidential_delivered().check_policy(None),
        Ok(None)
    );
}

#[test]
fn every_rail_reads_its_disclosure_layout() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.confidential_packed().disclosure_layout(),
        Ok(DisclosureLayout::Packed(PackedLayout {
            outputs: 2,
            exits: true,
            key_escrow: true,
            data_free: false,
        }))
    );
    assert_eq!(
        fixture.confidential_delivered().disclosure_layout(),
        Ok(DisclosureLayout::Delivered(DeliveredLayout {
            outputs: 8,
            exits: true,
            key_escrow: false,
        }))
    );
    assert_eq!(
        fixture.anonymous().disclosure_layout(),
        Ok(DisclosureLayout::Anonymous(AnonymousLayout {
            key: AnonymousAuditKey::Commitment { class: 4 },
            inputs: 3,
            outputs: 4,
            exits: true,
        }))
    );
    assert_eq!(
        fixture.anonymous_entry().disclosure_layout(),
        Ok(DisclosureLayout::Anonymous(AnonymousLayout {
            key: AnonymousAuditKey::Entry,
            inputs: 2,
            outputs: 2,
            exits: true,
        }))
    );
    assert_eq!(
        fixture.delegate_delivered().disclosure_layout(),
        Ok(DisclosureLayout::Delivered(DeliveredLayout {
            outputs: 8,
            exits: false,
            key_escrow: true,
        }))
    );
}

#[test]
fn the_rail_follows_the_instruction_and_the_ring_mode() {
    use InstructionTag::{DelegateTransact, Transact};
    let delegate = Address::new_from_array([0xd1; 32]);
    let ring = |mode: RingMode, has_policy: u8| {
        let mut config = config();
        config.mode = mode as u8;
        config.has_policy = has_policy;
        if mode == RingMode::Registry {
            config.delegate = delegate;
        }
        config
    };
    assert_eq!(
        RingRail::new(Transact, &ring(RingMode::Off, 0)),
        Ok(RingRail::Confidential)
    );
    assert_eq!(
        RingRail::new(Transact, &ring(RingMode::Anonymous, 1)),
        Ok(RingRail::Anonymous)
    );
    assert_eq!(
        RailSigner::new(DelegateTransact, &ring(RingMode::Registry, 1)),
        Ok(RailSigner::Delegate(delegate))
    );
    assert_eq!(
        RingRail::new(DelegateTransact, &ring(RingMode::Anonymous, 1)),
        Err(CustomRingError::AnonymousRingRefused)
    );
    assert_eq!(
        RingRail::new(DelegateTransact, &ring(RingMode::Off, 1)),
        Err(CustomRingError::DelegateDisabled)
    );
    assert_eq!(
        RingRail::new(InstructionTag::Merge, &ring(RingMode::Off, 1)),
        Err(CustomRingError::InvalidInstructionData)
    );
    let mut unknown = ring(RingMode::Off, 0);
    unknown.mode = RingMode::Anonymous as u8 + 1;
    assert_eq!(unknown.mode(), Err(CustomRingError::InvalidRingMode));
    assert_eq!(
        RingRail::new(Transact, &unknown),
        Err(CustomRingError::InvalidRingMode)
    );
}

#[test]
fn the_audit_statement_reads_the_frame_salt_and_the_policy_sender() {
    let fixture = Fixture::new();
    let parsed = ParsedTransact::new(fixture.anonymous()).unwrap();
    let data = parsed.data();
    let binding = AuditBinding {
        ring_id: &fixture.fields[60],
        auditor_pubkey: &config().auditor_pubkey,
        epoch: 41,
        first_contact_root: &fixture.fields[61],
        key_escrow: false,
    };
    let statement = parsed.audit_statement(binding).unwrap();
    assert_eq!(statement.head.first_nullifier, &data.nullifiers[0]);
    assert_eq!(statement.head.salt, data.salt);
    assert_eq!(statement.head.layout.value(), 0b0101);
    assert_eq!(statement.disclosure, data.disclosure);
    let AuditKind::Anonymous(anonymous) = statement.kind else {
        panic!("an anonymous rail binds the anonymous tail");
    };
    assert_eq!(anonymous.sender_commitment, &fixture.fields[4]);
    assert_eq!(
        (anonymous.epoch, anonymous.first_contact_root),
        (41, &fixture.fields[61])
    );
    let delivered = ParsedTransact::new(fixture.confidential_delivered()).unwrap();
    assert_eq!(
        delivered.audit_statement(binding).unwrap().kind,
        AuditKind::Delivered
    );
}

#[test]
fn a_key_escrow_flag_off_the_ring_mode_is_refused() {
    let fixture = Fixture::new();
    let config = config();
    let binding = |key_escrow| AuditBinding {
        ring_id: &fixture.fields[60],
        auditor_pubkey: &config.auditor_pubkey,
        epoch: 0,
        first_contact_root: &fixture.fields[61],
        key_escrow,
    };
    let statement = |data: &RingTransactData<'_>, key_escrow| {
        ParsedTransact::new(data.clone())
            .unwrap()
            .audit_statement(binding(key_escrow))
            .map(|statement| statement.head.layout.value())
    };
    let escrowed = fixture.confidential_packed();
    assert_eq!(
        statement(&escrowed, false),
        Err(CustomRingError::FlagNotAllowed)
    );
    assert_eq!(statement(&escrowed, true), Ok(0b0011));
    assert_eq!(
        statement(&fixture.confidential_delivered(), true),
        Err(CustomRingError::FlagNotAllowed)
    );
    let mut anonymous = fixture.anonymous();
    anonymous.key_escrow = true;
    assert_eq!(
        statement(&fixture.with_disclosure(anonymous), false),
        Err(CustomRingError::FlagNotAllowed)
    );
    let mut delegate = fixture.delegate();
    delegate.key_escrow = false;
    assert_eq!(
        statement(&fixture.with_disclosure(delegate), true),
        Err(CustomRingError::FlagNotAllowed)
    );
}
