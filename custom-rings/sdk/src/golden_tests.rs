//! Prover request bodies pinned byte for byte, the Go prover decodes the same files.
//! `UPDATE_PROVER_JSON=1` rewrites them.

use std::path::PathBuf;

use zolana_hasher::primitives::right_align;
use zolana_keypair::{ViewingKey, X25519Pubkey, X25519Secret};

/// The Go circuit tests' scalars, byte `i` is `seed ^ i` and byte 0 is 1.
pub(crate) const TX_SK: [u8; 32] = scalar(0x11);
pub(crate) const EPH_SK: [u8; 32] = scalar(0x22);
const AUDITOR_SK: [u8; 32] = scalar(0x33);

const fn scalar(seed: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let mut index = 0;
    while index < 32 {
        bytes[index] = seed ^ index as u8;
        index += 1;
    }
    bytes[0] = 1;
    bytes
}

pub(crate) fn key(secret: [u8; 32]) -> ViewingKey {
    ViewingKey::from_bytes(&secret).expect("canonical scalar")
}

pub(crate) fn auditor() -> X25519Pubkey {
    X25519Secret::from_bytes(&AUDITOR_SK)
        .expect("any 32 bytes")
        .pubkey()
}

/// A field element below the BN254 modulus that differs per `seed`.
pub(crate) fn field(seed: u64) -> [u8; 32] {
    let mut value = right_align(&seed.to_be_bytes());
    value[1] = seed as u8;
    value
}

pub(crate) fn assert_golden(name: &str, body: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/prover-json")
        .join(format!("{name}.json"));
    if std::env::var_os("UPDATE_PROVER_JSON").is_some() {
        std::fs::create_dir_all(path.parent().expect("fixture dir")).expect("fixture dir");
        std::fs::write(&path, body).expect("write fixture");
        return;
    }
    let pinned = std::fs::read_to_string(&path).expect("pinned fixture");
    assert!(
        pinned == body,
        "{name} request drifted from {}",
        path.display()
    );
}

mod bodies {
    use custom_ring_interface::{EscrowKey, MAX_RING_DEPOSIT_AUDIT_SLOTS, MEMBER_REGISTRY_HEIGHT};
    use solana_address::Address;
    use zeroize::Zeroizing;
    use zolana_client::{prover::ProveRequest, ProofInputUtxo};
    use zolana_keypair::{NullifierKey, X25519Secret};
    use zolana_ring_client::{NullifierKeyEnvelope, SealedNullifierKey};
    use zolana_ring_member_registry::MemberRegistryTree;
    use zolana_ring_policy::{ListId, Member, OutflowLimit, PolicySource};

    use super::{assert_golden, auditor, field, key, EPH_SK, TX_SK};
    use crate::{
        member_registry::tests::{current, response, tip},
        member_registry::{BatchPlan, ReadMemberRecord, RegistryTip},
        pipeline::PolicyRequest,
        prover::{RingCircuit, RingRequest},
        request::{
            AuditSecrets, BaseBody, CustomRingOpening, CustomRingOutputOpening, DepositBody,
            PolicyBody, RecordWitness, SubjectWitness,
        },
        trees::TransactRoots,
        witness::{CustomRingWitness, PolicyTree},
        CurrentRegistryRoot, CustomRing, MemberWrite, OutflowLimitProofInput, PolicyReads,
        PoolTree, RegistryBinding,
    };

    fn secrets(salt: u8) -> AuditSecrets {
        AuditSecrets {
            private_tx_hash: field(2),
            tx_viewing_key: key(TX_SK),
            ephemeral_sk: Zeroizing::new(EPH_SK),
            auditor_key: auditor(),
            salt: [salt; 16],
        }
    }

    fn opening(seed: u64) -> CustomRingOpening {
        CustomRingOpening {
            domain: field(seed),
            tree_id: field(seed + 1),
            owner_pk_hash: field(seed + 2),
            nullifier_pk: field(seed + 3),
            asset: field(seed + 4),
            amount: field(seed + 5),
            blinding: field(seed + 6),
            data_hash: field(seed + 7),
            ring_data_hash: field(seed + 8),
            ring_program_id: field(seed + 9),
        }
    }

    fn tree(id: u16, seed: u64) -> PolicyTree {
        PolicyTree {
            tree: PoolTree::from_id(id),
            roots: TransactRoots {
                state: field(seed),
                state_index: 0,
                nullifier: field(seed + 1),
                nullifier_index: 0,
            },
        }
    }

    fn subject(seed: u64, present: bool) -> SubjectWitness {
        SubjectWitness {
            present,
            record: RecordWitness {
                next: field(seed),
                lists: seed,
                escrow_key: field(seed + 1),
                index: seed + 2,
                path: (0..MEMBER_REGISTRY_HEIGHT as u64)
                    .map(|level| field(seed + 10 + level))
                    .collect(),
            },
            low_member: field(seed + 3),
            low_next: field(seed + 4),
            low_lists: seed + 5,
            low_escrow: field(seed + 6),
        }
    }

    fn policy() -> PolicyBody {
        let two = |index: usize, value: [u8; 32]| if index < 2 { value } else { [0; 32] };
        let mut subjects: [Option<SubjectWitness>; 9] = Default::default();
        subjects[0] = Some(subject(800, true));
        subjects[1] = Some(subject(900, false));
        subjects[5] = Some(subject(1000, true));
        let mut foreign_subjects: [Option<SubjectWitness>; 9] = Default::default();
        foreign_subjects[5] = Some(subject(1100, false));
        PolicyBody {
            circuit_type: RingCircuit::Policy,
            public_input_hash: field(1),
            audit: secrets(5),
            witness: Box::new(CustomRingWitness {
                indexed: None,
                registry: RegistryBinding::default(),
                foreign: None,
                n_in: 2,
                n_out: 3,
                inputs: core::array::from_fn(|index| opening(10 + 16 * index as u64)),
                outputs: core::array::from_fn(|index| CustomRingOutputOpening {
                    opening: opening(100 + 16 * index as u64),
                    ct_hash: if index == 0 { field(700) } else { [0; 32] },
                }),
                address_chain: (),
                private_tx_blinding: field(3),
                sources: core::array::from_fn(|index| PolicySource {
                    list_id: if index < 2 { index as u8 + 1 } else { 0 },
                    registry: if index == 1 { field(200) } else { [0; 32] },
                }),
                policy_len: 2,
                rules: core::array::from_fn(|index| two(index, field(220 + index as u64))),
                inline_assets: core::array::from_fn(|index| field(300 + index as u64)),
                inline_limits: core::array::from_fn(|index| 1_000 * index as u64),
                inline_count: 2,
                limits: OutflowLimitProofInput {
                    limits: core::array::from_fn(|index| OutflowLimit {
                        asset: field(610 + index as u64),
                        cap: if index < 2 { 50_000 } else { 0 },
                        cosign_above: if index == 1 { 7_000 } else { 0 },
                    }),
                    limit_count: 2,
                    ring_id: field(601),
                    namespace_owner_hash: field(602),
                    approval_required: true,
                },
                trees: vec![tree(4, 400)],
                address_tree_id: 4,
                key_escrow: true,
                member_registry_root: field(500),
                subjects,
                foreign_root: field(501),
                foreign_subjects,
            }),
        }
    }

    fn wrapped(circuit: RingCircuit) -> String {
        let request = PolicyRequest {
            body: policy(),
            indexed: None,
            reads: PolicyReads {
                trees: Vec::new(),
                registry: RegistryBinding::default(),
                foreign: None,
            },
            approval_required: true,
            circuit,
        };
        request.request().unwrap().body().unwrap().to_string()
    }

    #[test]
    fn the_audit_and_policy_bodies_match_the_golden_files() {
        let outputs = (0..2u64)
            .map(|index| ProofInputUtxo {
                domain: field(30 + 10 * index),
                tree_id: field(31 + 10 * index),
                owner_hash: field(32 + 10 * index),
                asset: field(33 + 10 * index),
                amount: field(34 + 10 * index),
                blinding: field(35 + 10 * index),
                data_hash: field(36 + 10 * index),
                ring_data_hash: field(37 + 10 * index),
                ring_program_id: field(38 + 10 * index),
            })
            .collect();
        let base = BaseBody {
            circuit_type: RingCircuit::Base,
            public_input_hash: field(1),
            audit: secrets(7),
            n_out: 2,
            outputs,
        };
        assert_golden("custom-ring-base", &RingRequest(&base).body().unwrap());
        assert_golden(
            "custom-ring-policy",
            &RingRequest(&policy()).body().unwrap(),
        );
        assert_golden(
            "custom-ring-delegate-policy",
            &wrapped(RingCircuit::DelegatePolicy),
        );
    }

    #[test]
    fn the_deposit_body_matches_the_golden_file() {
        let slots = |seed: u64| {
            core::array::from_fn(|index| {
                if index < 2 {
                    field(seed + index as u64)
                } else {
                    [0; 32]
                }
            })
        };
        let mut members: [Option<RecordWitness>; MAX_RING_DEPOSIT_AUDIT_SLOTS] = Default::default();
        for (index, member) in members.iter_mut().take(2).enumerate() {
            *member = Some(RecordWitness {
                next: field(40 + index as u64),
                lists: 3,
                escrow_key: field(42 + index as u64),
                index: 5 + index as u64,
                path: (0..MEMBER_REGISTRY_HEIGHT as u64)
                    .map(|level| field(100 * (index as u64 + 1) + level))
                    .collect(),
            });
        }
        let body = DepositBody {
            circuit_type: RingCircuit::Deposit,
            public_input_hash: field(1),
            context_hash: field(2),
            count: 2,
            owner_pk_hashes: slots(10),
            nullifier_pks: slots(20),
            blindings: Zeroizing::new(slots(30)),
            ct_hashes: slots(50),
            members,
            ephemeral_sk: Zeroizing::new(EPH_SK),
            auditor_pk: auditor(),
            key_escrow: true,
            member_registry_root: field(9),
        };
        assert_golden("custom-ring-deposit", &RingRequest(&body).body().unwrap());
    }

    fn members() -> (Member, MemberRegistryTree) {
        let member = Member::owner_tag(&[9; 32]).unwrap();
        let mut tree = MemberRegistryTree::new().unwrap();
        let listed: Vec<_> = [3u8, 12]
            .into_iter()
            .map(|byte| (*Member::owner_tag(&[byte; 32]).unwrap().as_bytes(), 1))
            .collect();
        let items = tree.list_items(&listed).unwrap();
        tree.apply(&items).unwrap();
        (member, tree)
    }

    #[test]
    fn the_registration_body_matches_the_golden_file() {
        let ring = CustomRing::new(Address::new_from_array([5; 32]));
        let nullifier_key = NullifierKey::from_secret([7u8; 31]);
        let envelope = NullifierKeyEnvelope {
            ephemeral_sk: Zeroizing::new(EPH_SK),
            sealed: SealedNullifierKey {
                eph_pk: X25519Secret::from_bytes(&EPH_SK).unwrap().pubkey(),
                ciphertext: [0x2a; 32],
            },
            nullifier_pk: nullifier_key.pubkey().unwrap(),
        };
        let (member, mut tree) = members();
        // The member is listed, so the registration rewrites its record.
        let items = tree.list_items(&[(*member.as_bytes(), 4)]).unwrap();
        tree.apply(&items).unwrap();
        let read = ReadMemberRecord { ring, member }
            .decode(current(&tree, 2), response(&tree, &member, 2, None))
            .unwrap();
        let secret = Zeroizing::new(zolana_hasher::primitives::right_align(
            &nullifier_key.secret(),
        ));
        let (body, item) = crate::register_key::register(
            &envelope,
            auditor(),
            secret,
            &tip(&tree, 2),
            &read.opening,
        )
        .unwrap();
        let escrow_key = EscrowKey {
            nullifier_pk: &envelope.nullifier_pk,
            ciphertext: &envelope.sealed.ciphertext,
        }
        .hash()
        .unwrap();
        tree.apply(&[item]).unwrap();
        assert_eq!(body.registry_new_root, tree.root());
        assert_eq!(item.escrow_key, escrow_key);
        assert_golden(
            "custom-ring-register-key",
            &RingRequest(&body).body().unwrap(),
        );
    }

    #[test]
    fn the_member_batch_body_matches_the_golden_file() {
        let ring = CustomRing::new(Address::new_from_array([5; 32]));
        let (member, tree) = members();
        let writes = [
            MemberWrite::add(member, ListId::Allow),
            MemberWrite::add(Member::owner_tag(&[3; 32]).unwrap(), ListId::Block),
        ];
        let root = CurrentRegistryRoot {
            root: tree.root(),
            next_index: tree.next_index(),
            history_index: 1,
        };
        let records: Vec<_> = writes
            .iter()
            .map(|write| {
                ReadMemberRecord {
                    ring,
                    member: write.member,
                }
                .decode(root, response(&tree, &write.member, 1, None))
                .unwrap()
            })
            .collect();
        let tip = RegistryTip {
            root,
            append_path: tree.append_path().unwrap(),
        };
        let plan = BatchPlan::new(&tip, &writes, &records).unwrap();
        let mut reference = tree.clone();
        reference.apply(&plan.items).unwrap();
        assert_eq!(plan.new_root, reference.root());
        let body = plan.body(&tip).unwrap();
        assert_golden(
            "custom-ring-update-members",
            &RingRequest(&body).body().unwrap(),
        );
    }
}
