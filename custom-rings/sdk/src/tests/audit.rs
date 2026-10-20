use custom_ring_interface::{CustomRingBasePublicInput, CustomRingPolicyPublicInput};
use zolana_client::{prover::indexed::IndexedRegistry, ProofInputUtxo};
use zolana_interface::tree_slot::TreeSlot;
use zolana_ring_client::AuditError;
use zolana_ring_policy::{
    PolicySource, MAX_INLINE_ASSETS, MAX_RULES, MAX_SOURCES, POLICY_INPUT_SLOTS,
    POLICY_OUTPUT_SLOTS,
};

use crate::{
    golden_tests::{auditor, key, TX_SK},
    prover::RingCircuit,
    request::{CustomRingOpening, CustomRingOutputOpening},
    tests::support::ring,
    trees::TransactRoots,
    witness::{CustomRingWitness, IndexedRegistries, PolicyTree},
    CustomRingProofParams, EncryptedAudit, OutflowLimitProofInput, PoolTree, RegistryBinding,
    RingError, RingIdentity,
};

pub(super) const REGISTRY_ROOT: [u8; 32] = [12; 32];

/// The BN254 scalar modulus, the first big-endian value no field element reaches.
const MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

pub(super) fn tree(id: u16, root: u8) -> PolicyTree {
    PolicyTree {
        tree: PoolTree::from_id(id),
        roots: TransactRoots {
            state: [root; 32],
            state_index: 1,
            nullifier: [root + 1; 32],
            nullifier_index: 2,
        },
    }
}

/// An escrowed ring at history slot 3, no curator.
pub(super) fn witness() -> CustomRingWitness {
    CustomRingWitness {
        indexed: None,
        registry: RegistryBinding {
            root_index: 3,
            root: REGISTRY_ROOT,
        },
        foreign: None,
        n_in: 1,
        n_out: 1,
        inputs: vec![CustomRingOpening::default(); POLICY_INPUT_SLOTS],
        outputs: vec![CustomRingOutputOpening::default(); POLICY_OUTPUT_SLOTS],
        address_chain: (),
        private_tx_blinding: [0; 32],
        sources: [PolicySource::default(); MAX_SOURCES],
        policy_len: 0,
        rules: [[0; 32]; MAX_RULES],
        inline_assets: [[0; 32]; MAX_INLINE_ASSETS],
        inline_limits: [0; MAX_INLINE_ASSETS],
        inline_count: 0,
        limits: OutflowLimitProofInput::none(RingIdentity {
            ring_id: [10; 32],
            namespace_owner_hash: [11; 32],
        }),
        trees: vec![tree(0, 7)],
        address_tree_id: 0,
        key_escrow: true,
        member_registry_root: REGISTRY_ROOT,
        subjects: (0..crate::witness::SUBJECT_SLOTS).map(|_| None).collect(),
        foreign_root: [0; 32],
        foreign_subjects: (0..crate::witness::SUBJECT_SLOTS).map(|_| None).collect(),
    }
}

pub(super) fn encrypted(outputs: Vec<ProofInputUtxo>) -> EncryptedAudit {
    CustomRingProofParams {
        tx_viewing_key: key(TX_SK),
        auditor_pk: auditor(),
        salt: [3; 16],
        outputs,
    }
    .encrypt()
    .unwrap()
}

pub(super) fn private_tx_hash() -> [u8; 32] {
    let mut hash = [0; 32];
    hash[29..].copy_from_slice(&[0xab, 0xcd, 0xef]);
    hash
}

#[test]
fn ordinary_audit_key_follows_the_settled_output_count() {
    for count in 1..=4 {
        let body = encrypted(vec![ProofInputUtxo::default(); count])
            .pending
            .finish_base(private_tx_hash())
            .unwrap();
        assert_eq!(
            body.circuit_type,
            if count == 2 {
                RingCircuit::BaseConfidential
            } else {
                RingCircuit::Base
            }
        );
        assert_eq!(usize::from(body.n_out), count);
    }
}

/// The public input binds the tree slot, the escrow flag and both registry roots.
#[test]
fn finish_binds_the_public_input_the_program_recomputes() {
    let outputs = vec![ProofInputUtxo::default()];
    let EncryptedAudit { pending, message } = encrypted(outputs.clone());
    let policy_hash = [4; 32];
    let mut witness = witness();
    witness.foreign_root = [13; 32];
    witness.indexed = Some(IndexedRegistries {
        registry: IndexedRegistry {
            ring_program_id: ring().program_id(),
            root: REGISTRY_ROOT,
            next_index: 2,
        },
        foreign: None,
    });
    let proof = pending
        .finish(private_tx_hash(), Box::new(witness), &policy_hash)
        .unwrap();

    let slots = [TreeSlot::new(0, [7; 32], [8; 32])];
    let expected = CustomRingPolicyPublicInput {
        audit: CustomRingBasePublicInput {
            private_tx_hash: &private_tx_hash(),
            tx_viewing_pk: key(TX_SK).pubkey().as_bytes(),
            auditor_pk: auditor().as_bytes(),
            eph_pk: message.ephemeral_pubkey_bytes(),
            ciphertext: message.ciphertext(),
            output_body_hashes: &[[0; 32]],
            output_hashes: &[outputs[0].hash().unwrap()],
            salt: &[3; 16],
            disclosure: message.disclosure(),
            anonymous: false,
        },
        policy_hash: &policy_hash,
        tree_slots: &slots,
        address_tree_id: 0,
        ring_id: &[10; 32],
        namespace_owner_hash: &[11; 32],
        approval_required: false,
        key_escrow: true,
        member_registry_root: &REGISTRY_ROOT,
        foreign_root: &[13; 32],
    }
    .hash()
    .unwrap();

    assert_eq!(proof.body.public_input_hash, expected);
    assert_eq!(proof.body.audit.private_tx_hash, private_tx_hash());
    assert_eq!(proof.body.witness.tree_slots(), slots);
    let indexed = proof.indexed.as_ref().unwrap();
    assert_eq!(indexed.public_inputs.len(), 8);
    let mut transcript = indexed.public_inputs.clone();
    transcript.insert(
        1,
        zolana_interface::tree_slot::populated_tree_slots_hash_chain(&slots).unwrap(),
    );
    assert_eq!(
        zolana_hasher::hash_chain::create_hash_chain_from_slice(&transcript).unwrap(),
        expected
    );
    assert_eq!(indexed.trees.len(), 1);
    assert_eq!(indexed.trees[0].utxo_root, [7; 32]);
    assert_eq!(indexed.registry.next_index, 2);
    assert!(indexed.foreign_registry.is_none());
}

#[test]
fn the_base_statement_binds_the_same_audit_fields() {
    let outputs = vec![ProofInputUtxo::default(); 2];
    let EncryptedAudit { pending, message } = encrypted(outputs.clone());
    let body = pending.finish_base(private_tx_hash()).unwrap();
    let hashes: Vec<_> = outputs
        .iter()
        .map(|output| output.hash().unwrap())
        .collect();
    let tx_viewing_pk = key(TX_SK).pubkey();
    let auditor_pk = auditor();
    let statement = CustomRingBasePublicInput {
        private_tx_hash: &private_tx_hash(),
        tx_viewing_pk: tx_viewing_pk.as_bytes(),
        auditor_pk: auditor_pk.as_bytes(),
        eph_pk: message.ephemeral_pubkey_bytes(),
        ciphertext: message.ciphertext(),
        output_body_hashes: &[[0; 32]; 2],
        output_hashes: &hashes,
        salt: &[3; 16],
        disclosure: message.disclosure(),
        anonymous: false,
    };
    // The confidential key proves the audit elements alone.
    let expected = zolana_hasher::hash_chain::create_hash_chain_from_slice(
        &statement.audit_elements().unwrap(),
    )
    .unwrap();
    assert_eq!(body.circuit_type, RingCircuit::BaseConfidential);
    assert_eq!(body.public_input_hash, expected);
    assert_ne!(statement.hash().unwrap(), expected);
    assert_eq!(body.n_out, 2);
}

#[test]
fn a_hash_at_the_modulus_is_refused() {
    let mut below = MODULUS;
    below[31] -= 1;
    assert!(encrypted(vec![ProofInputUtxo::default()])
        .pending
        .finish_base(below)
        .is_ok());
    for hash in [MODULUS, [0xff; 32]] {
        let pending = encrypted(vec![ProofInputUtxo::default()]).pending;
        assert!(matches!(
            pending.finish_base(hash),
            Err(RingError::NonCanonicalHash)
        ));
        let pending = encrypted(vec![ProofInputUtxo::default()]).pending;
        assert!(matches!(
            pending.finish(hash, Box::new(witness()), &[4; 32]),
            Err(RingError::NonCanonicalHash)
        ));
    }
}

#[test]
fn an_audit_without_outputs_or_past_the_policy_slots_is_refused() {
    for count in [0, POLICY_OUTPUT_SLOTS + 1] {
        let refused = CustomRingProofParams {
            tx_viewing_key: key(TX_SK),
            auditor_pk: auditor(),
            salt: [3; 16],
            outputs: vec![ProofInputUtxo::default(); count],
        }
        .encrypt();
        assert!(matches!(
            refused,
            Err(RingError::Audit(AuditError::OutputCount(got))) if got == count
        ));
    }
}

#[test]
fn every_encryption_mints_its_own_ephemeral_key() {
    let first = encrypted(vec![ProofInputUtxo::default()]).message;
    let second = encrypted(vec![ProofInputUtxo::default()]).message;
    assert_ne!(
        first.ephemeral_pubkey_bytes(),
        second.ephemeral_pubkey_bytes()
    );
    assert_ne!(first.ciphertext(), second.ciphertext());
}
