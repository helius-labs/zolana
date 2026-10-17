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
    use custom_ring_interface::{RegisteredKey, MAX_RING_DEPOSIT_AUDIT_SLOTS};
    use solana_address::Address;
    use zeroize::Zeroizing;
    use zolana_client::{prover::ProveRequest, ProofInputUtxo};
    use zolana_indexer_api::{Context, GetRingKeyRegistryRegisterProofResponse, Hash};
    use zolana_keypair::{NullifierKey, X25519Secret};
    use zolana_ring_client::{NullifierKeyEnvelope, SealedNullifierKey};
    use zolana_ring_key_registry::{KeyRegistryTree, Registration};
    use zolana_ring_policy::{Member, OutflowLimit, SourceOwner, ANSWER_SLOTS};

    use super::{assert_golden, auditor, field, key, EPH_SK, TX_SK};
    use crate::{
        escrow::RegistryKeyOpening,
        pipeline::PolicyRequest,
        prover::{RingCircuit, RingRequest},
        request::{
            AnonymousBase, AnonymousFlag, AnonymousIdentities, AuditSecrets, BaseBody,
            CustomRingOpening, DepositBody, Escrow, PolicyBody, RuleAnswer, IDENTITY_LEN,
        },
        trees::TransactRoots,
        witness::{CustomRingWitness, PolicyTree},
        CurrentKeyRegistryRoot, CustomRing, EscrowBinding, OutflowLimitProofInput, PolicyReads,
        PoolTree,
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

    fn opening(seed: u64, key: Option<RegistryKeyOpening>) -> CustomRingOpening {
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
            key,
        }
    }

    /// Two Solana recipients, the trailing slots stay zero.
    fn identities() -> AnonymousIdentities {
        let identity = |seed: u8| {
            let mut identity = [seed; IDENTITY_LEN];
            identity[0] = zolana_hasher::primitives::SOLANA_OWNER_TAG;
            identity
        };
        let viewing = |seed: u8| {
            *X25519Secret::from_bytes(&[seed; 32])
                .unwrap()
                .pubkey()
                .as_bytes()
        };
        AnonymousIdentities {
            flag: AnonymousFlag,
            sender: identity(0x41),
            recipients: core::array::from_fn(|index| match index < 2 {
                true => identity(0x42 + index as u8),
                false => [0; IDENTITY_LEN],
            }),
            recipient_viewing_keys: core::array::from_fn(|index| match index < 2 {
                true => viewing(0x44 + index as u8),
                false => [0; IDENTITY_LEN],
            }),
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

    fn answer(index: usize) -> RuleAnswer {
        if index >= 2 {
            return RuleAnswer::default();
        }
        let seed = 800 + 100 * index as u64;
        RuleAnswer {
            enabled: true,
            tree_slot: index as u8,
            mode: index as u8,
            list_id: 2 - index as u8,
            state: 1,
            absent_branch: 1 + index as u8,
            member: field(seed),
            content_hash: field(seed + 1),
            version: 4,
            blinding: field(seed + 2),
            low: field(seed + 3),
            next: field(seed + 4),
            nullifier_path: (0..40).map(|level| field(seed + 10 + level)).collect(),
            nullifier_path_index: 11,
            state_path: (0..32).map(|level| field(seed + 60 + level)).collect(),
            state_path_index: 12,
        }
    }

    fn policy() -> PolicyBody {
        policy_with(None)
    }

    fn policy_with(anonymous: Option<AnonymousIdentities>) -> PolicyBody {
        let registry_key = RegistryKeyOpening {
            next: field(700),
            ct_hash: field(701),
            index: 3,
            path: core::array::from_fn(|index| field(710 + index as u64)),
        };
        let two = |index: usize, value: [u8; 32]| if index < 2 { value } else { [0; 32] };
        PolicyBody {
            circuit_type: RingCircuit::Policy,
            public_input_hash: field(1),
            audit: secrets(5),
            anonymous,
            witness: Box::new(CustomRingWitness {
                indexed: None,
                indexed_registry: None,
                n_in: 2,
                n_out: 3,
                inputs: core::array::from_fn(|index| opening(10 + 16 * index as u64, None)),
                outputs: core::array::from_fn(|index| {
                    opening(
                        100 + 16 * index as u64,
                        (index == 0).then_some(registry_key),
                    )
                }),
                address_chain: (),
                private_tx_blinding: field(3),
                sources: core::array::from_fn(|index| SourceOwner {
                    list_id: if index < 2 { index as u8 + 1 } else { 0 },
                    owner_hash: two(index, field(200 + index as u64)),
                }),
                policy_len: 2,
                rules: core::array::from_fn(|index| two(index, field(220 + index as u64))),
                inline_assets: core::array::from_fn(|index| field(300 + index as u64)),
                inline_limits: core::array::from_fn(|index| 1_000 * index as u64),
                inline_count: 2,
                trees: vec![tree(4, 400), tree(9, 402)],
                address_tree_id: 4,
                escrow: Escrow(Some(CurrentKeyRegistryRoot {
                    root: field(500),
                    next_index: 1,
                    history_index: 0,
                })),
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
                answers: (0..ANSWER_SLOTS).map(answer).collect(),
                revocation_targets: [[0; 32]; ANSWER_SLOTS],
                revocation_tree_indexes: [0; ANSWER_SLOTS],
            }),
        }
    }

    fn wrapped(circuit: RingCircuit) -> String {
        let request = PolicyRequest {
            body: policy(),
            indexed: None,
            reads: PolicyReads {
                trees: Vec::new(),
                escrow: EscrowBinding::Off,
                revocation_targets: [[0; 32]; ANSWER_SLOTS],
                revocation_tree_indexes: [0; ANSWER_SLOTS],
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
        let mut base = BaseBody {
            circuit_type: RingCircuit::Base,
            public_input_hash: field(1),
            audit: secrets(7),
            n_out: 2,
            outputs,
            anonymous: None,
        };
        assert_golden("custom-ring-base", &RingRequest(&base).body().unwrap());
        base.anonymous = Some(AnonymousBase {
            identities: identities(),
            n_in: 2,
            inputs: core::array::from_fn(|index| opening(1_000 + 16 * index as u64, None)),
            anonymous_outputs: core::array::from_fn(|index| {
                opening(1_100 + 16 * index as u64, None)
            }),
            private_tx_blinding: field(3),
        });
        assert_golden(
            "custom-ring-base-anonymous",
            &RingRequest(&base).body().unwrap(),
        );
        assert_golden(
            "custom-ring-policy-anonymous",
            &RingRequest(&policy_with(Some(identities())))
                .body()
                .unwrap(),
        );
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
        let mut keys = [None; MAX_RING_DEPOSIT_AUDIT_SLOTS];
        for (index, key) in keys.iter_mut().take(2).enumerate() {
            *key = Some(RegistryKeyOpening {
                next: field(40 + index as u64),
                ct_hash: field(42 + index as u64),
                index: 5 + index as u64,
                path: core::array::from_fn(|level| field(100 * (index as u64 + 1) + level as u64)),
            });
        }
        let mut body = DepositBody {
            circuit_type: RingCircuit::Deposit,
            public_input_hash: field(1),
            context_hash: field(2),
            count: 2,
            anonymous: false,
            owner_pk_hashes: slots(10),
            owner_keys: None,
            nullifier_pks: slots(20),
            blindings: Zeroizing::new(slots(30)),
            keys,
            ephemeral_sk: Zeroizing::new(EPH_SK),
            auditor_pk: auditor(),
            key_escrow: true,
            key_registry_root: field(9),
        };
        assert_golden("custom-ring-deposit", &RingRequest(&body).body().unwrap());
        // An anonymous ring escrows no key, each opening discloses its Ed25519 owner.
        body.anonymous = true;
        body.owner_keys = Some(slots(50));
        body.keys = [None; MAX_RING_DEPOSIT_AUDIT_SLOTS];
        body.key_escrow = false;
        body.key_registry_root = [0; 32];
        assert_golden(
            "custom-ring-deposit-anonymous",
            &RingRequest(&body).body().unwrap(),
        );
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
        let member = Member::owner_tag(&[9; 32]).unwrap();
        let mut tree = KeyRegistryTree::new().unwrap();
        for byte in [3u8, 12] {
            tree.register(Registration {
                member: *Member::owner_tag(&[byte; 32]).unwrap().as_bytes(),
                key: [byte; 32],
            })
            .unwrap();
        }
        let inserted = tree
            .register(Registration {
                member: *member.as_bytes(),
                key: RegisteredKey {
                    nullifier_pk: &envelope.nullifier_pk,
                    ciphertext: &envelope.sealed.ciphertext,
                }
                .hash()
                .unwrap(),
            })
            .unwrap();
        let query = ring.member_proof_request(
            &member,
            CurrentKeyRegistryRoot {
                root: inserted.old_root,
                next_index: inserted.new_index,
                history_index: 0,
            },
        );
        let response = GetRingKeyRegistryRegisterProofResponse {
            context: Context::default(),
            root: Hash(inserted.old_root),
            next_index: inserted.new_index,
            member: Hash(inserted.member),
            low_member: Hash(inserted.low_member),
            low_next: Hash(inserted.low_next),
            low_key_hash: Hash(inserted.low_key),
            low_index: inserted.low_index,
            low_proof: inserted.low_proof.into_iter().map(Hash).collect(),
            new_proof: inserted.new_proof.into_iter().map(Hash).collect(),
        };
        let secret = Zeroizing::new(zolana_hasher::primitives::right_align(
            &nullifier_key.secret(),
        ));
        let (body, _) =
            crate::key_registry::register(&envelope, auditor(), secret, &query, response).unwrap();
        assert_golden(
            "custom-ring-register-key",
            &RingRequest(&body).body().unwrap(),
        );
    }
}
