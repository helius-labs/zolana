use custom_ring_interface::{CustomRingBasePublicInput, CustomRingPolicyPublicInput};
use zolana_client::ProofInputUtxo;
use zolana_interface::tree_slot::TreeSlot;
use zolana_ring_client::AuditError;
use zolana_ring_policy::{
    SourceOwner, ANSWER_SLOTS, MAX_INLINE_ASSETS, MAX_RULES, MAX_SOURCES, POLICY_INPUT_SLOTS,
    POLICY_OUTPUT_SLOTS,
};

use crate::{
    golden_tests::{auditor, key, TX_SK},
    request::{CustomRingOpening, Escrow},
    trees::TransactRoots,
    witness::{CustomRingWitness, PolicyTree},
    CurrentKeyRegistryRoot, CustomRingProofParams, EncryptedAudit, OutflowLimitProofInput,
    PoolTree, RingError, RingIdentity,
};

const REGISTRY_ROOT: [u8; 32] = [12; 32];

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

/// Fact 1 reads the second tree, the registry root is the history slot 3 root.
pub(super) fn witness() -> CustomRingWitness {
    let mut revocation_targets = [[0; 32]; ANSWER_SLOTS];
    revocation_targets[0] = [0x21; 32];
    revocation_targets[1] = [0x22; 32];
    let mut revocation_tree_indexes = [0; ANSWER_SLOTS];
    revocation_tree_indexes[1] = 1;
    CustomRingWitness {
        indexed: None,
        indexed_registry: None,
        n_in: 1,
        n_out: 1,
        inputs: [CustomRingOpening::default(); POLICY_INPUT_SLOTS],
        outputs: [CustomRingOpening::default(); POLICY_OUTPUT_SLOTS],
        address_chain: (),
        private_tx_blinding: [0; 32],
        sources: [SourceOwner::default(); MAX_SOURCES],
        policy_len: 0,
        rules: [[0; 32]; MAX_RULES],
        inline_assets: [[0; 32]; MAX_INLINE_ASSETS],
        inline_limits: [0; MAX_INLINE_ASSETS],
        inline_count: 0,
        trees: vec![tree(0, 7), tree(4, 9)],
        address_tree_id: 0,
        escrow: Escrow(Some(CurrentKeyRegistryRoot {
            root: REGISTRY_ROOT,
            next_index: 2,
            history_index: 3,
        })),
        limits: OutflowLimitProofInput::none(RingIdentity {
            ring_id: [10; 32],
            namespace_owner_hash: [11; 32],
        }),
        answers: Vec::new(),
        revocation_targets,
        revocation_tree_indexes,
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

/// The public input binds every tree slot, the per-fact tree indexes and the registry root.
#[test]
fn finish_binds_the_public_input_the_program_recomputes() {
    let outputs = vec![ProofInputUtxo::default()];
    let EncryptedAudit { pending, message } = encrypted(outputs.clone());
    let policy_hash = [4; 32];
    let mut witness = witness();
    witness.indexed = Some(Vec::new());
    let revocation_targets = witness.revocation_targets;
    let revocation_tree_indexes = witness.revocation_tree_indexes;
    let proof = pending
        .finish(private_tx_hash(), Box::new(witness), &policy_hash)
        .unwrap();

    let slots = [
        TreeSlot::new(0, [7; 32], [8; 32]),
        TreeSlot::new(4, [9; 32], [10; 32]),
    ];
    let expected = CustomRingPolicyPublicInput {
        audit: CustomRingBasePublicInput {
            private_tx_hash: &private_tx_hash(),
            tx_viewing_pk: key(TX_SK).pubkey().as_bytes(),
            auditor_pk: auditor().as_bytes(),
            eph_pk: message.ephemeral_pubkey_bytes(),
            ciphertext: message.ciphertext(),
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
        key_registry_root: Some(&REGISTRY_ROOT),
        revocation_tree_indexes: &revocation_tree_indexes,
        revocation_targets: &revocation_targets,
    }
    .hash()
    .unwrap();

    assert_eq!(proof.body.public_input_hash, expected);
    assert_eq!(proof.body.audit.private_tx_hash, private_tx_hash());
    assert_eq!(proof.body.witness.tree_slots(), slots);
    let indexed = proof.indexed.as_ref().unwrap();
    let mut transcript = indexed.public_inputs.clone();
    transcript.insert(
        1,
        zolana_interface::tree_slot::populated_tree_slots_hash_chain(&slots).unwrap(),
    );
    assert_eq!(
        zolana_hasher::hash_chain::create_hash_chain_from_slice(&transcript).unwrap(),
        expected
    );
    assert_eq!(indexed.trees.len(), 2);
    assert_eq!(indexed.trees[1].id, 4);
    assert_eq!(indexed.trees[1].utxo_root, [9; 32]);
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
    let expected = CustomRingBasePublicInput {
        private_tx_hash: &private_tx_hash(),
        tx_viewing_pk: key(TX_SK).pubkey().as_bytes(),
        auditor_pk: auditor().as_bytes(),
        eph_pk: message.ephemeral_pubkey_bytes(),
        ciphertext: message.ciphertext(),
        output_hashes: &hashes,
        salt: &[3; 16],
        disclosure: message.disclosure(),
        anonymous: false,
    }
    .hash()
    .unwrap();
    assert_eq!(body.public_input_hash, expected);
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
