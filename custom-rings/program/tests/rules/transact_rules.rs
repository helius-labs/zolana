//! The transact refusals ahead of either ring pairing.

use custom_ring_interface::{
    input_flag,
    key_catalog::RingCircuit,
    shape_flag,
    stream::{RingTag, EPOCH_SLOTS, TAG_LEN},
    tag, transact_flag, AnchorRoot, AnonymousProofData, AppliedAt, CustomRingError,
    CustomRingProof, InputTrees, MemberRegistry, PlainGroth16Proof, PolicyProof, RingOutput,
    RingProgramConfig, RingRail, RingTransactData, SetCoSignerIxData, WithdrawalThreshold,
    GRACE_SLOTS, MEMBER_REGISTRY_PDA_SEED,
};
use solana_address::Address;
use solana_bn254::compression::prelude::alt_bn128_g2_compress_be;
use solana_instruction::AccountMeta;
use solana_keypair::{Keypair, Signer};
use zolana_interface::{
    instruction::{InterfaceTransfer, TreeContext},
    shape::{ring_authority_shapes, SPP_SUPPORTED_SHAPES},
    state::{default_tree_fees, discriminator::TREE_ACCOUNT_DISCRIMINATOR, nullifier_tree_params},
    MAX_INTERFACE_TRANSFERS, RING_TRANSACT_RING_CONFIG_INDEX, SHIELDED_POOL_PROGRAM_ID,
    TRANSACT_PAYER_INDEX,
};
use zolana_tree::{TreeAccount, UTXO_TREE_HEIGHT};

use crate::common::{
    allow_list_table, config_pda, config_write, delegate_ring, floored, off_curve_g2, on_curve_g2,
    policy_write, reaches_verification, refused, registry_pda, ring_auth, transact, Ring, Sent,
    Setup, SYSTEM,
};

pub const SPP: Address = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);

/// A canonical field value, never zero.
fn field(seed: u8) -> [u8; 32] {
    let mut value = [seed; 32];
    value[0] = 0x0f;
    value
}

pub struct Fixture {
    proofs: [CustomRingProof; 2],
    spp_proof: PlainGroth16Proof,
    fields: Vec<[u8; 32]>,
    keys: [[u8; 32]; 16],
    bodies: [[u8; 40]; 16],
    tags: [[u8; TAG_LEN]; 16],
    ciphertext: Vec<u8>,
    salt: [u8; 16],
}

impl Fixture {
    pub fn new() -> Self {
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
                proof_b: alt_bn128_g2_compress_be(&on_curve_g2()).unwrap(),
                proof_c: [0x32; 32],
            },
            fields: (1..=120u8).map(field).collect(),
            keys: core::array::from_fn(|i| [0x40 + i as u8; 32]),
            bodies: core::array::from_fn(|i| [0x80 + i as u8; 40]),
            tags: core::array::from_fn(|i| [0xa0 + i as u8; TAG_LEN]),
            ciphertext: (0..82).collect(),
            salt: [0x5c; 16],
        }
    }

    /// One input per shape input slot, every output a ring output of the rail.
    pub fn transfer(
        &self,
        rail: RingRail,
        n_in: u8,
        n_out: u8,
        policy: bool,
    ) -> RingTransactData<'_> {
        let mut data = RingTransactData {
            rail,
            n_in,
            n_out,
            audit_proof: &self.proofs[0],
            policy: policy.then(|| PolicyProof {
                proof: &self.proofs[1],
                own_root_index: 0,
                curator_root_index: None,
                sender_commitment: (rail == RingRail::Anonymous).then_some(&self.fields[3]),
            }),
            approval_required: false,
            previous_epoch: false,
            anchor: None,
            expiry_unix_ts: 1_800_000_000,
            tx_viewing_u: &self.keys[0],
            salt: &self.salt,
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            data_free: false,
            key_escrow: rail == RingRail::Delegate,
            full_openings: false,
            outputs: Vec::new(),
            eph_u: &self.keys[1],
            sealed: &self.keys[2],
            disclosure: &[],
            private_tx_hash: &self.fields[0],
            anonymous: (rail == RingRail::Anonymous).then(|| AnonymousProofData {
                commitment: &self.keys[3],
                commitment_pok: &self.keys[4],
                default_owner_tag: None,
            }),
            spp_proof: &self.spp_proof,
            nullifiers: &self.fields[1..1 + usize::from(n_in)],
            input_trees: InputTrees::One(TreeContext {
                utxo_tree_root_index: 1,
                nullifier_tree_root_index: 2,
            }),
        };
        let slots = 0..usize::from(n_out);
        data.outputs = match (rail, n_out) {
            (RingRail::Anonymous, _) => slots
                .map(|slot| RingOutput::Anonymous {
                    hash: &self.fields[10 + slot],
                    tag: RingTag::from_bytes(self.tags[slot]),
                    body: &self.bodies[slot],
                })
                .collect(),
            (RingRail::Confidential | RingRail::Delegate, 8 | 16) => slots
                .map(|slot| RingOutput::Delivered {
                    hash: &self.fields[10 + slot],
                    u: &self.keys[5 + slot % 10],
                    body: &self.bodies[slot],
                })
                .collect(),
            _ => slots
                .map(|slot| RingOutput::Packed {
                    hash: &self.fields[10 + slot],
                    u: &self.keys[5 + slot],
                    ciphertext: &self.ciphertext,
                })
                .collect(),
        };
        self.disclose(&mut data);
        data
    }

    /// Publishes the field count the data's layout takes.
    pub fn disclose<'a>(&'a self, data: &mut RingTransactData<'a>) {
        let count = data.disclosure_layout().unwrap().field_count();
        data.disclosure = &self.fields[40..40 + count];
    }
}

/// The forwarded SPP list, the payer first, `owners` as the owner signer run.
pub fn spp_list(
    payer: &Address,
    data: &RingTransactData<'_>,
    owners: &[AccountMeta],
) -> Vec<AccountMeta> {
    let trees = match data.input_trees {
        InputTrees::One(_) => 1,
        InputTrees::Two { .. } => 2,
    };
    let mut accounts = vec![
        AccountMeta::new(*payer, true),
        AccountMeta::new(Address::new_unique(), false),
        AccountMeta::new_readonly(SPP, false),
        AccountMeta::new_readonly(SYSTEM, false),
        AccountMeta::new(ring_auth(), false),
    ];
    accounts.extend(
        (0..trees + data.nullifiers.len()).map(|_| AccountMeta::new(Address::new_unique(), false)),
    );
    accounts.extend_from_slice(owners);
    accounts
}

pub fn send(
    ring: &mut Ring,
    instruction_tag: u8,
    prefix: Vec<AccountMeta>,
    bytes: Vec<u8>,
    spp: Vec<AccountMeta>,
    signers: &[&Keypair],
) -> Sent {
    let accounts = [
        vec![AccountMeta::new_readonly(config_pda(), false)],
        prefix,
        spp,
    ]
    .concat();
    ring.send(transact(instruction_tag, accounts, bytes), signers)
}

pub fn registry_meta() -> AccountMeta {
    AccountMeta::new_readonly(registry_pda(), false)
}

/// The payer repeated as the one owner signer, the lean confidential set.
fn payer_owner(ring: &Ring) -> Vec<AccountMeta> {
    vec![AccountMeta::new_readonly(ring.payer.pubkey(), true)]
}

/// A confidential transfer from the payer, `prefix` after the config.
fn confidential(ring: &mut Ring, prefix: Vec<AccountMeta>, data: &RingTransactData<'_>) -> Sent {
    let spp = spp_list(&ring.payer.pubkey(), data, &payer_owner(ring));
    send(
        ring,
        tag::TRANSACT,
        prefix,
        data.encode().unwrap(),
        spp,
        &[],
    )
}

#[test]
fn a_confidential_transfer_passing_every_check_reaches_the_audit_key() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    reaches_verification(confidential(
        &mut ring,
        Vec::new(),
        &fixture.transfer(RingRail::Confidential, 2, 2, false),
    ));
    let mut ring = Ring::new(Setup::Policy);
    reaches_verification(confidential(
        &mut ring,
        vec![registry_meta()],
        &fixture.transfer(RingRail::Confidential, 2, 2, true),
    ));
}

#[test]
fn trailing_bytes_or_a_packed_output_count_past_the_capacity_disagree_with_the_shape() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    let data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    let spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(&ring));
    let mut bytes = data.encode().unwrap();
    bytes.push(0);
    refused(
        send(
            &mut ring,
            tag::TRANSACT,
            Vec::new(),
            bytes,
            spp.clone(),
            &[],
        ),
        CustomRingError::RingTransactLength,
    );

    let mut bytes = data.encode().unwrap();
    let (flags_shape_and_inputs, leg_count) = (input_flag::BYTE + 1, 1);
    let output_count = flags_shape_and_inputs
        + CustomRingProof::SIZE
        + core::mem::size_of_val(&data.expiry_unix_ts)
        + data.tx_viewing_u.len()
        + data.salt.len()
        + leg_count;
    assert_eq!(bytes[output_count], 2);
    for count in [3, 70] {
        bytes[output_count] = count;
        refused(
            send(
                &mut ring,
                tag::TRANSACT,
                Vec::new(),
                bytes.clone(),
                spp.clone(),
                &[],
            ),
            CustomRingError::RingTransactLength,
        );
    }
}

#[test]
fn flags_follow_the_rings_mode_and_policy() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    let data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    let mut bytes = data.encode().unwrap();
    bytes[transact_flag::BYTE] |= transact_flag::ANCHOR;
    let spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(&ring));
    refused(
        send(&mut ring, tag::TRANSACT, Vec::new(), bytes, spp, &[]),
        CustomRingError::FlagNotAllowed,
    );
    refused(
        confidential(
            &mut ring,
            Vec::new(),
            &fixture.transfer(RingRail::Confidential, 2, 2, true),
        ),
        CustomRingError::UnexpectedPolicyProof,
    );
    let mut policy_ring = Ring::new(Setup::Policy);
    refused(
        confidential(&mut policy_ring, vec![registry_meta()], &data),
        CustomRingError::MissingPolicyProof,
    );
}

#[test]
fn the_previous_epoch_at_epoch_zero_underflows() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Anonymous);
    let mut data = fixture.transfer(RingRail::Anonymous, 2, 2, false);
    let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    ring.warp(EPOCH_SLOTS - 1);
    data.previous_epoch = true;
    refused(
        send(
            &mut ring,
            tag::TRANSACT,
            Vec::new(),
            data.encode().unwrap(),
            spp.clone(),
            &[],
        ),
        CustomRingError::EpochUnderflow,
    );
    ring.warp(EPOCH_SLOTS);
    reaches_verification(send(
        &mut ring,
        tag::TRANSACT,
        Vec::new(),
        data.encode().unwrap(),
        spp,
        &[],
    ));
}

#[test]
fn a_policy_transfer_takes_exactly_one_owner_signer() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    let second = Keypair::new();
    let owners = [
        AccountMeta::new_readonly(ring.payer.pubkey(), true),
        AccountMeta::new_readonly(second.pubkey(), true),
    ];
    let spp = spp_list(&ring.payer.pubkey(), &data, &owners);
    refused(
        send(
            &mut ring,
            tag::TRANSACT,
            vec![registry_meta()],
            data.encode().unwrap(),
            spp,
            &[&second],
        ),
        CustomRingError::OwnerSignerCount,
    );
    let repeated = [owners[0].clone(), owners[0].clone()];
    let spp = spp_list(&ring.payer.pubkey(), &data, &repeated);
    reaches_verification(send(
        &mut ring,
        tag::TRANSACT,
        vec![registry_meta()],
        data.encode().unwrap(),
        spp,
        &[],
    ));
    let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    refused(
        send(
            &mut ring,
            tag::TRANSACT,
            vec![registry_meta()],
            data.encode().unwrap(),
            spp,
            &[],
        ),
        CustomRingError::OwnerSignerCount,
    );
}

#[test]
fn every_confidential_owner_slot_signs() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    let data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    let owners = [AccountMeta::new_readonly(Keypair::new().pubkey(), false)];
    let spp = spp_list(&ring.payer.pubkey(), &data, &owners);
    refused(
        send(
            &mut ring,
            tag::TRANSACT,
            Vec::new(),
            data.encode().unwrap(),
            spp,
            &[],
        ),
        CustomRingError::MissingOwnerSigner,
    );
}

#[test]
fn an_anonymous_transfer_takes_no_signer_but_the_payer() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Anonymous);
    let data = fixture.transfer(RingRail::Anonymous, 2, 2, false);
    let owner = Keypair::new();
    let spp = spp_list(
        &ring.payer.pubkey(),
        &data,
        &[AccountMeta::new_readonly(owner.pubkey(), true)],
    );
    refused(
        send(
            &mut ring,
            tag::TRANSACT,
            Vec::new(),
            data.encode().unwrap(),
            spp,
            &[&owner],
        ),
        CustomRingError::InvalidAnonymousSigner,
    );
}

#[test]
fn an_off_curve_spp_point_is_refused_before_either_pairing() {
    let mut fixture = Fixture::new();
    fixture.spp_proof.proof_b = off_curve_g2();
    let mut ring = Ring::new(Setup::AuditOnly);
    refused(
        confidential(
            &mut ring,
            Vec::new(),
            &fixture.transfer(RingRail::Confidential, 2, 2, false),
        ),
        CustomRingError::InvalidSppProofPoint,
    );
}

#[test]
fn a_published_zero_disclosure_field_is_refused() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    let mut fields = data.disclosure.to_vec();
    fields[3] = [0; 32];
    data.disclosure = &fields;
    refused(
        confidential(&mut ring, Vec::new(), &data),
        CustomRingError::ZeroDisclosureField,
    );
}

#[test]
fn a_key_escrow_bit_off_the_ring_mode_is_refused() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.key_escrow = true;
    fixture.disclose(&mut data);
    refused(
        confidential(&mut ring, vec![registry_meta()], &data),
        CustomRingError::FlagNotAllowed,
    );

    let mut registry_ring = delegate_ring(&Keypair::new());
    reaches_verification(confidential(
        &mut registry_ring,
        vec![registry_meta()],
        &data,
    ));
    data.key_escrow = false;
    fixture.disclose(&mut data);
    refused(
        confidential(&mut registry_ring, vec![registry_meta()], &data),
        CustomRingError::FlagNotAllowed,
    );
}

#[test]
fn a_default_ring_spend_takes_the_entry_key_up_to_eight_inputs() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Anonymous);
    let mut data = fixture.transfer(RingRail::Anonymous, 2, 2, false);
    data.full_openings = true;
    fixture.disclose(&mut data);
    let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    reaches_verification(send(
        &mut ring,
        tag::TRANSACT,
        Vec::new(),
        data.encode().unwrap(),
        spp,
        &[],
    ));

    let wide = fixture.transfer(RingRail::Anonymous, 12, 2, false);
    let spp = spp_list(&ring.payer.pubkey(), &wide, &[]);
    let mut bytes = wide.encode().unwrap();
    reaches_verification(send(
        &mut ring,
        tag::TRANSACT,
        Vec::new(),
        bytes.clone(),
        spp.clone(),
        &[],
    ));
    bytes[input_flag::BYTE] |= input_flag::FULL_OPENINGS;
    refused(
        send(&mut ring, tag::TRANSACT, Vec::new(), bytes, spp, &[]),
        CustomRingError::RingShapeUnkeyed,
    );
}

/// The compact bytes of a `test-vectors/ring-transact-expansion.json` case.
fn vector_case(name: &str) -> Vec<u8> {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/ring-transact-expansion.json"
    )))
    .unwrap();
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap();
    hex::decode(case["compact"].as_str().unwrap()).unwrap()
}

#[test]
fn the_vector_transfers_without_public_legs_reach_their_keys() {
    let mut audit_only = Ring::new(Setup::AuditOnly);
    let bytes = vector_case("confidential_delivered_audit_only");
    let data = RingTransactData::parse(&bytes, RingRail::Confidential)
        .unwrap()
        .into_data();
    let spp = spp_list(&audit_only.payer.pubkey(), &data, &payer_owner(&audit_only));
    reaches_verification(send(
        &mut audit_only,
        tag::TRANSACT,
        Vec::new(),
        bytes.clone(),
        spp,
        &[],
    ));

    let mut anonymous = Ring::new(Setup::Anonymous);
    let bytes = vector_case("anonymous_entry_audit_only");
    let parsed = RingTransactData::parse(&bytes, RingRail::Anonymous).unwrap();
    let data = parsed.data();
    assert_eq!(
        RingCircuit::audit(parsed.layout(), data.n_out),
        RingCircuit::AnonymousEntryAudit {
            class: 8,
            outputs: data.n_out
        }
    );
    let spp = spp_list(&anonymous.payer.pubkey(), data, &[]);
    reaches_verification(send(
        &mut anonymous,
        tag::TRANSACT,
        Vec::new(),
        bytes.clone(),
        spp,
        &[],
    ));

    let delegate = Keypair::new();
    let mut registry_ring = delegate_ring(&delegate);
    for name in ["delegate_move", "delegate_delivered_move"] {
        let bytes = vector_case(name);
        let data = RingTransactData::parse(&bytes, RingRail::Delegate)
            .unwrap()
            .into_data();
        reaches_verification(delegate_move(
            &mut registry_ring,
            &delegate,
            &data,
            bytes.clone(),
        ));
    }
}

#[test]
fn an_own_root_one_write_below_the_floor_is_refused() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.policy = data.policy.map(|policy| PolicyProof {
        own_root_index: 1,
        ..policy
    });
    let base: MemberRegistry = ring.read(&registry_pda());
    ring.write(&registry_pda(), &floored(&base, 4, 5));
    refused(
        confidential(&mut ring, vec![registry_meta()], &data),
        CustomRingError::RootBelowFloor,
    );
    ring.write(&registry_pda(), &floored(&base, 5, 5));
    reaches_verification(confidential(&mut ring, vec![registry_meta()], &data));
}

#[test]
fn a_policy_ring_without_a_table_refuses_transfers() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let mut registry: MemberRegistry = ring.read(&registry_pda());
    registry.policy_hash = [0; 32];
    ring.write(&registry_pda(), &registry);
    refused(
        confidential(
            &mut ring,
            vec![registry_meta()],
            &fixture.transfer(RingRail::Confidential, 2, 2, true),
        ),
        CustomRingError::PolicyNotSet,
    );
}

/// A curator registry of another ring program, history slot 1 applied at position 4.
struct Curator {
    address: Address,
}

#[derive(Clone, Copy, Default)]
struct Floor {
    floor: u64,
    prior_floor: u64,
    floor_slot: u64,
}

impl Curator {
    const PROGRAM: Address = Address::new_from_array([0x63; 32]);

    fn install(ring: &mut Ring, floor: Floor) -> Self {
        Self::install_under(ring, Self::PROGRAM, floor)
    }

    fn install_under(ring: &mut Ring, program: Address, floor: Floor) -> Self {
        let (address, bump) = Address::find_program_address(&[MEMBER_REGISTRY_PDA_SEED], &program);
        let mut registry = MemberRegistry::new(bump, 0);
        registry.push_root(
            field(8),
            AppliedAt {
                applied: 4,
                slot: 10,
            },
        );
        registry.floor = floor.floor.to_le_bytes();
        registry.prior_floor = floor.prior_floor.to_le_bytes();
        registry.floor_slot = floor.floor_slot.to_le_bytes();
        ring.store(address, program, bytemuck::bytes_of(&registry).to_vec());
        Self { address }
    }

    /// Sources the ring's allow list from the curator.
    fn source(&self, ring: &mut Ring) {
        let mut table = allow_list_table(Vec::new());
        table.sources[0].source = 1;
        let authority = ring.authority.insecure_clone();
        ring.send(
            policy_write(
                tag::SET_POLICY_RULES,
                &authority.pubkey(),
                table,
                &[self.address],
            ),
            &[&authority],
        )
        .expect("source the allow list from the curator");
    }

    fn transfer(&self, ring: &mut Ring, data: &RingTransactData<'_>) -> Sent {
        confidential(
            ring,
            vec![
                registry_meta(),
                AccountMeta::new_readonly(self.address, false),
            ],
            data,
        )
    }
}

fn curator_transfer(fixture: &Fixture) -> RingTransactData<'_> {
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.policy = data.policy.map(|policy| PolicyProof {
        curator_root_index: Some(1),
        ..policy
    });
    data
}

#[test]
fn a_curator_root_below_the_floor_lives_only_through_the_grace_window() {
    let fixture = Fixture::new();
    let data = curator_transfer(&fixture);
    let raised_at = 1_000;
    let mut ring = Ring::new(Setup::Policy);
    let curator = Curator::install(
        &mut ring,
        Floor {
            floor: 5,
            prior_floor: 3,
            floor_slot: raised_at,
        },
    );
    curator.source(&mut ring);
    ring.warp(raised_at + GRACE_SLOTS - 1);
    reaches_verification(curator.transfer(&mut ring, &data));
    ring.warp(raised_at + GRACE_SLOTS);
    refused(
        curator.transfer(&mut ring, &data),
        CustomRingError::CuratorRootStale,
    );
}

#[test]
fn a_second_floor_raise_refuses_roots_below_the_first() {
    let fixture = Fixture::new();
    let raised_at = 1_000;
    let mut ring = Ring::new(Setup::Policy);
    let curator = Curator::install(
        &mut ring,
        Floor {
            floor: 6,
            prior_floor: 5,
            floor_slot: raised_at,
        },
    );
    curator.source(&mut ring);
    ring.warp(raised_at);
    refused(
        curator.transfer(&mut ring, &curator_transfer(&fixture)),
        CustomRingError::CuratorRootStale,
    );
}

#[test]
fn the_curator_account_must_be_the_sourced_registry() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let curator = Curator::install(&mut ring, Floor::default());
    curator.source(&mut ring);
    let impostor = Curator::install_under(
        &mut ring,
        Address::new_from_array([0x64; 32]),
        Floor::default(),
    );
    refused(
        impostor.transfer(&mut ring, &curator_transfer(&fixture)),
        CustomRingError::InvalidCuratorRegistry,
    );
    reaches_verification(curator.transfer(&mut ring, &curator_transfer(&fixture)));
}

fn set_co_signer(
    ring: &mut Ring,
    co_signer: &Address,
    scope: u8,
    thresholds: Vec<WithdrawalThreshold>,
) {
    let authority = ring.authority.insecure_clone();
    let data = SetCoSignerIxData {
        signer: co_signer.to_bytes(),
        scope,
        thresholds,
    };
    ring.send(
        config_write(
            tag::SET_CO_SIGNER,
            &authority.pubkey(),
            &[],
            &wincode::serialize(&data).unwrap(),
        ),
        &[&authority],
    )
    .expect("set the co-signer");
}

#[test]
fn a_demanded_co_signer_signs_with_the_configured_key() {
    let fixture = Fixture::new();
    let data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    let co_signer = Keypair::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    set_co_signer(&mut ring, &co_signer.pubkey(), 1, Vec::new());
    let spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(&ring));
    refused(
        send(
            &mut ring,
            tag::TRANSACT,
            vec![AccountMeta::new_readonly(co_signer.pubkey(), false)],
            data.encode().unwrap(),
            spp.clone(),
            &[],
        ),
        CustomRingError::MissingCoSigner,
    );
    let other = Keypair::new();
    refused(
        send(
            &mut ring,
            tag::TRANSACT,
            vec![AccountMeta::new_readonly(other.pubkey(), true)],
            data.encode().unwrap(),
            spp.clone(),
            &[&other],
        ),
        CustomRingError::UnauthorizedCoSigner,
    );
    reaches_verification(send(
        &mut ring,
        tag::TRANSACT,
        vec![AccountMeta::new_readonly(co_signer.pubkey(), true)],
        data.encode().unwrap(),
        spp,
        &[&co_signer],
    ));
}

/// The payer withdraws `amount` SOL as the one owner, `prefix` after the config.
fn withdraw(ring: &mut Ring, amount: u64, prefix: Vec<AccountMeta>, signers: &[&Keypair]) -> Sent {
    let fixture = Fixture::new();
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    data.interface_transfers = vec![InterfaceTransfer::SolWithdrawal { amount }];
    let mut spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(ring));
    spp.extend([
        AccountMeta::new(Address::new_unique(), false),
        AccountMeta::new(Address::new_unique(), false),
    ]);
    send(
        ring,
        tag::TRANSACT,
        prefix,
        data.encode().unwrap(),
        spp,
        signers,
    )
}

const SOL_THRESHOLD: WithdrawalThreshold = WithdrawalThreshold {
    mint: [0; 32],
    amount: 100,
};

#[test]
fn a_withdrawal_above_its_threshold_demands_the_co_signer() {
    let co_signer = Keypair::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    set_co_signer(&mut ring, &co_signer.pubkey(), 4, vec![SOL_THRESHOLD]);
    reaches_verification(withdraw(&mut ring, 100, Vec::new(), &[]));
    refused(
        withdraw(
            &mut ring,
            101,
            vec![AccountMeta::new_readonly(co_signer.pubkey(), false)],
            &[],
        ),
        CustomRingError::MissingCoSigner,
    );
    reaches_verification(withdraw(
        &mut ring,
        101,
        vec![AccountMeta::new_readonly(co_signer.pubkey(), true)],
        &[&co_signer],
    ));
}

#[test]
fn a_withdrawal_co_signed_by_its_own_owner_is_refused() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let owner = ring.payer.insecure_clone();
    set_co_signer(&mut ring, &owner.pubkey(), 4, vec![SOL_THRESHOLD]);
    reaches_verification(withdraw(&mut ring, 100, Vec::new(), &[]));
    refused(
        withdraw(
            &mut ring,
            1_000,
            vec![AccountMeta::new_readonly(owner.pubkey(), true)],
            &[&owner],
        ),
        CustomRingError::CoSignerIsOwner,
    );
}

#[test]
fn the_approval_flag_needs_an_outflow_limit_and_a_co_signer() {
    let fixture = Fixture::new();
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.approval_required = true;
    let mut ring = Ring::new(Setup::Policy);
    refused(
        confidential(&mut ring, vec![registry_meta()], &data),
        CustomRingError::UnexpectedApproval,
    );
    let mut limited = Ring::new(Setup::LimitedPolicy);
    refused(
        confidential(&mut limited, vec![registry_meta()], &data),
        CustomRingError::ApprovalWithoutCoSigner,
    );
}

#[test]
fn an_approval_co_signed_by_its_own_owner_is_refused() {
    let fixture = Fixture::new();
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.approval_required = true;
    let mut ring = Ring::new(Setup::LimitedPolicy);
    let co_signed = |ring: &mut Ring, co_signer: &Keypair| {
        let spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(ring));
        let prefix = vec![
            registry_meta(),
            AccountMeta::new_readonly(co_signer.pubkey(), true),
        ];
        send(
            ring,
            tag::TRANSACT,
            prefix,
            data.encode().unwrap(),
            spp,
            &[co_signer],
        )
    };
    let owner = ring.payer.insecure_clone();
    set_co_signer(&mut ring, &owner.pubkey(), 4, Vec::new());
    refused(
        co_signed(&mut ring, &owner),
        CustomRingError::CoSignerIsOwner,
    );
    let co_signer = Keypair::new();
    set_co_signer(&mut ring, &co_signer.pubkey(), 4, Vec::new());
    reaches_verification(co_signed(&mut ring, &co_signer));
}

/// A confidential transfer from the payer settling `transfers`, `funder` at each funder slot.
fn settle(ring: &mut Ring, transfers: Vec<InterfaceTransfer>, funder: &AccountMeta) -> Sent {
    let fixture = Fixture::new();
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    data.interface_transfers = transfers;
    let mut spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(ring));
    for transfer in &data.interface_transfers {
        let mut group: Vec<AccountMeta> = (0..transfer.settlement_account_count())
            .map(|_| AccountMeta::new(Address::new_unique(), false))
            .collect();
        if let Some(position) = transfer.funder_account_position() {
            group[position] = funder.clone();
        }
        spp.extend(group);
    }
    send(
        ring,
        tag::TRANSACT,
        Vec::new(),
        data.encode().unwrap(),
        spp,
        &[],
    )
}

#[test]
fn public_legs_are_refused_with_the_rings_own_errors() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let payer = AccountMeta::new(ring.payer.pubkey(), true);
    refused(
        settle(
            &mut ring,
            vec![InterfaceTransfer::SolWithdrawal { amount: 0 }],
            &payer,
        ),
        CustomRingError::ZeroPublicLegAmount,
    );
    refused(
        settle(
            &mut ring,
            vec![
                InterfaceTransfer::SolDeposit { amount: 5 },
                InterfaceTransfer::SolWithdrawal { amount: 5 },
            ],
            &payer,
        ),
        CustomRingError::ZeroNetPublicAmount,
    );
    let mints = InterfaceTransfer::SplWithdrawal {
        amount: 9,
        spl_interface_bump: 255,
    };
    refused(
        settle(
            &mut ring,
            vec![
                InterfaceTransfer::SolWithdrawal { amount: 7 },
                mints,
                mints,
                mints,
            ],
            &payer,
        ),
        CustomRingError::TooManyPublicAssets,
    );
    refused(
        settle(
            &mut ring,
            vec![InterfaceTransfer::SolWithdrawal { amount: u64::MAX }; 2],
            &payer,
        ),
        CustomRingError::PublicAmountOverflow,
    );
    let unsigned = AccountMeta::new(Address::new_unique(), false);
    refused(
        settle(
            &mut ring,
            vec![InterfaceTransfer::SolDeposit { amount: 5 }],
            &unsigned,
        ),
        CustomRingError::MissingFundingSigner,
    );
}

#[test]
fn public_legs_fit_the_account_list_and_the_leg_cap() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    let spl = InterfaceTransfer::SplWithdrawal {
        amount: 9,
        spl_interface_bump: 255,
    };
    data.interface_transfers = vec![spl; 4];
    let spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(&ring));
    refused(
        send(
            &mut ring,
            tag::TRANSACT,
            Vec::new(),
            data.encode().unwrap(),
            spp,
            &[],
        ),
        CustomRingError::InvalidSettlementAccounts,
    );
    let legs = MAX_INTERFACE_TRANSFERS + 1;
    data.interface_transfers = vec![InterfaceTransfer::SolWithdrawal { amount: 1 }; legs];
    let mut spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(&ring));
    let settlement = AccountMeta::new(Address::new_unique(), false);
    spp.extend(std::iter::repeat_n(settlement, 2 * legs));
    refused(
        send(
            &mut ring,
            tag::TRANSACT,
            Vec::new(),
            data.encode().unwrap(),
            spp,
            &[],
        ),
        CustomRingError::TooManyPublicLegs,
    );
}

#[test]
fn the_forwarded_list_holds_the_ring_pda_and_a_signing_payer() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    let data = fixture.transfer(RingRail::Confidential, 2, 2, false);
    for (index, error) in [
        (
            RING_TRANSACT_RING_CONFIG_INDEX,
            CustomRingError::MissingRingAuth,
        ),
        (TRANSACT_PAYER_INDEX, CustomRingError::MissingFundingSigner),
    ] {
        let mut spp = spp_list(&ring.payer.pubkey(), &data, &payer_owner(&ring));
        spp[index] = AccountMeta::new(Address::new_unique(), false);
        refused(
            send(
                &mut ring,
                tag::TRANSACT,
                Vec::new(),
                data.encode().unwrap(),
                spp,
                &[],
            ),
            error,
        );
    }
}

#[test]
fn an_own_root_index_past_the_written_history_is_refused() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.policy = data.policy.map(|policy| PolicyProof {
        own_root_index: 3,
        ..policy
    });
    refused(
        confidential(&mut ring, vec![registry_meta()], &data),
        CustomRingError::RootIndexEmpty,
    );
}

#[test]
fn the_ring_pda_in_the_owner_signer_run_is_refused() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Anonymous);
    let data = fixture.transfer(RingRail::Anonymous, 2, 2, false);
    let spp = spp_list(
        &ring.payer.pubkey(),
        &data,
        &[AccountMeta::new_readonly(ring_auth(), false)],
    );
    refused(
        send(
            &mut ring,
            tag::TRANSACT,
            Vec::new(),
            data.encode().unwrap(),
            spp,
            &[],
        ),
        CustomRingError::RingAuthOutOfSlot,
    );
}

#[test]
fn only_the_configured_delegate_moves_and_settles_no_public_leg() {
    let fixture = Fixture::new();
    let delegate = Keypair::new();
    let mut ring = delegate_ring(&delegate);
    let mut data = fixture.transfer(RingRail::Delegate, 2, 2, true);
    let prefix = |signer: &Keypair| {
        vec![
            registry_meta(),
            AccountMeta::new_readonly(signer.pubkey(), true),
        ]
    };
    let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    let other = Keypair::new();
    refused(
        send(
            &mut ring,
            tag::DELEGATE_TRANSACT,
            prefix(&other),
            data.encode().unwrap(),
            spp.clone(),
            &[&other],
        ),
        CustomRingError::UnauthorizedDelegate,
    );
    reaches_verification(send(
        &mut ring,
        tag::DELEGATE_TRANSACT,
        prefix(&delegate),
        data.encode().unwrap(),
        spp.clone(),
        &[&delegate],
    ));
    data.interface_transfers = vec![InterfaceTransfer::SolWithdrawal { amount: 5 }];
    let mut settled = spp;
    settled.extend([
        AccountMeta::new(Address::new_unique(), false),
        AccountMeta::new(Address::new_unique(), false),
    ]);
    refused(
        send(
            &mut ring,
            tag::DELEGATE_TRANSACT,
            prefix(&delegate),
            data.encode().unwrap(),
            settled,
            &[&delegate],
        ),
        CustomRingError::DelegatePublicLeg,
    );
    let mut audit_only = Ring::new(Setup::AuditOnly);
    let data = fixture.transfer(RingRail::Delegate, 2, 2, true);
    let spp = spp_list(&audit_only.payer.pubkey(), &data, &[]);
    refused(
        send(
            &mut audit_only,
            tag::DELEGATE_TRANSACT,
            prefix(&delegate),
            data.encode().unwrap(),
            spp,
            &[&delegate],
        ),
        CustomRingError::DelegateDisabled,
    );
}

#[test]
fn a_delegate_move_co_signed_by_the_delegate_is_refused() {
    let fixture = Fixture::new();
    let delegate = Keypair::new();
    let mut ring = delegate_ring(&delegate);
    let data = fixture.transfer(RingRail::Delegate, 2, 2, true);
    let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    let co_signed = |ring: &mut Ring, co_signer: &Keypair| {
        let prefix = vec![
            registry_meta(),
            AccountMeta::new_readonly(co_signer.pubkey(), true),
            AccountMeta::new_readonly(delegate.pubkey(), true),
        ];
        send(
            ring,
            tag::DELEGATE_TRANSACT,
            prefix,
            data.encode().unwrap(),
            spp.clone(),
            &[co_signer, &delegate],
        )
    };
    set_co_signer(&mut ring, &delegate.pubkey(), 1, Vec::new());
    refused(
        co_signed(&mut ring, &delegate),
        CustomRingError::CoSignerIsDelegate,
    );
    let co_signer = Keypair::new();
    set_co_signer(&mut ring, &co_signer.pubkey(), 1, Vec::new());
    reaches_verification(co_signed(&mut ring, &co_signer));
}

fn delegate_move(
    ring: &mut Ring,
    delegate: &Keypair,
    data: &RingTransactData<'_>,
    bytes: Vec<u8>,
) -> Sent {
    let spp = spp_list(&ring.payer.pubkey(), data, &[]);
    send(
        ring,
        tag::DELEGATE_TRANSACT,
        vec![
            registry_meta(),
            AccountMeta::new_readonly(delegate.pubkey(), true),
        ],
        bytes,
        spp,
        &[delegate],
    )
}

#[test]
fn every_ring_authority_shape_reaches_the_delegate_key_lookup() {
    let fixture = Fixture::new();
    let delegate = Keypair::new();
    let mut ring = delegate_ring(&delegate);
    for shape in ring_authority_shapes() {
        let n_in = u8::try_from(shape.n_inputs()).unwrap();
        let n_out = u8::try_from(shape.n_outputs()).unwrap();
        let mut data = fixture.transfer(RingRail::Delegate, n_in, n_out, true);
        data.nullifiers = &fixture.fields[1..2];
        let bytes = data.encode().unwrap();
        reaches_verification(delegate_move(&mut ring, &delegate, &data, bytes));
    }
}

#[test]
fn a_delegate_shape_without_a_ring_authority_key_is_refused() {
    let fixture = Fixture::new();
    let delegate = Keypair::new();
    let mut ring = delegate_ring(&delegate);
    let data = fixture.transfer(RingRail::Delegate, 2, 2, true);
    let mut bytes = data.encode().unwrap();
    let unkeyed = SPP_SUPPORTED_SHAPES
        .iter()
        .position(|shape| !shape.is_ring_authority())
        .expect("an SPP shape the ring authority rail refuses");
    bytes[shape_flag::BYTE] = u8::try_from(unkeyed).unwrap();
    refused(
        delegate_move(&mut ring, &delegate, &data, bytes),
        CustomRingError::RingShapeUnkeyed,
    );
}

pub fn spp_tree(address: &Address, paused: bool) -> Vec<u8> {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let params = nullifier_tree_params();
    let fees = default_tree_fees(params.input_queue_zkp_batch_size).unwrap();
    TreeAccount::init(
        &mut bytes,
        TREE_ACCOUNT_DISCRIMINATOR,
        UTXO_TREE_HEIGHT as u8,
        address.to_bytes(),
        1,
        params,
        fees,
    )
    .unwrap()
    .set_paused(paused);
    bytes
}

#[test]
fn a_first_contact_root_comes_from_a_live_spp_state_tree() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Anonymous);
    let mut data = fixture.transfer(RingRail::Anonymous, 2, 2, false);
    let tree = Address::new_unique();
    let mut anchored = |ring: &mut Ring, root_index: u16| {
        data.anchor = Some(AnchorRoot {
            tree: 1,
            root_index,
        });
        let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
        send(
            ring,
            tag::TRANSACT,
            vec![AccountMeta::new_readonly(tree, false)],
            data.encode().unwrap(),
            spp,
            &[],
        )
    };
    refused(
        anchored(&mut ring, 0),
        CustomRingError::FirstContactRootMissing,
    );
    ring.store(tree, SPP, spp_tree(&tree, false));
    reaches_verification(anchored(&mut ring, 0));
    refused(
        anchored(&mut ring, 1),
        CustomRingError::FirstContactRootMissing,
    );
    ring.store(tree, SPP, spp_tree(&tree, true));
    refused(
        anchored(&mut ring, 0),
        CustomRingError::FirstContactTreePaused,
    );
}

#[test]
fn a_config_of_another_owner_is_refused() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    let config: RingProgramConfig = ring.read(&config_pda());
    ring.store(
        config_pda(),
        Curator::PROGRAM,
        bytemuck::bytes_of(&config).to_vec(),
    );
    refused(
        confidential(
            &mut ring,
            Vec::new(),
            &fixture.transfer(RingRail::Confidential, 2, 2, false),
        ),
        CustomRingError::ConfigNotInitialized,
    );
}
