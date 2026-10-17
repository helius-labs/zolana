//! A child of `member_registry`, the batch plan and the tip fetch are private to it.

use custom_ring_interface::{EscrowKey, MemberRecord, MemberUpdate, MEMBER_REGISTRY_HEIGHT};
use solana_address::Address;
use zeroize::Zeroizing;
use zolana_client::ProveRequest;
use zolana_hasher::primitives::right_align;
use zolana_indexer_api::{
    Base64String, Context, GetRingMemberRecordResponse, Hash, RingLowRecordView,
    RingMemberRecordView,
};
use zolana_keypair::{NullifierKey, X25519Secret};
use zolana_ring_client::{NullifierKeyEnvelope, SealedNullifierKey};
use zolana_ring_member_registry::{MemberRegistryTree, Opening};
use zolana_ring_policy::{ListId, ListSet, Member};

use super::*;
use crate::{prover::RingRequest, register_key::register, tests::support::ring};

pub(crate) fn member(byte: u8) -> Member {
    Member::owner_tag(&[byte; 32]).unwrap()
}

/// The indexer's answer for `member` under the tree's current root, at history slot `cursor`.
pub(crate) fn response(
    tree: &MemberRegistryTree,
    member: &Member,
    cursor: u8,
    sealed: Option<&SealedNullifierKey>,
) -> GetRingMemberRecordResponse {
    let context = Context::default();
    let (root, next_index) = (Hash(tree.root()), tree.next_index());
    match tree.opening(member.as_bytes()).unwrap() {
        Opening::Present {
            record,
            index,
            path,
        } => GetRingMemberRecordResponse {
            context,
            root,
            root_index: cursor,
            next_index,
            present: true,
            record: Some(RingMemberRecordView {
                member: Hash(record.member),
                next: Hash(record.next),
                lists: record.lists,
                escrow_key: Hash(record.escrow_key),
                eph_pk: sealed.map(|sealed| Base64String(sealed.eph_pk.as_bytes().to_vec())),
                ciphertext: sealed.map(|sealed| Base64String(sealed.ciphertext.to_vec())),
            }),
            index,
            path: path.into_iter().map(Hash).collect(),
            low: None,
        },
        Opening::Absent {
            low,
            low_index,
            path,
        } => GetRingMemberRecordResponse {
            context,
            root,
            root_index: cursor,
            next_index,
            present: false,
            record: None,
            index: 0,
            path: Vec::new(),
            low: Some(RingLowRecordView {
                member: Hash(low.member),
                next: Hash(low.next),
                lists: low.lists,
                escrow_key: Hash(low.escrow_key),
                index: low_index,
                path: path.into_iter().map(Hash).collect(),
            }),
        },
    }
}

pub(crate) fn current(tree: &MemberRegistryTree, cursor: u8) -> CurrentRegistryRoot {
    CurrentRegistryRoot {
        root: tree.root(),
        next_index: tree.next_index(),
        history_index: cursor,
    }
}

pub(crate) fn tip(tree: &MemberRegistryTree, cursor: u8) -> RegistryTip {
    RegistryTip {
        root: current(tree, cursor),
        append_path: tree.append_path().unwrap(),
    }
}

fn read(member: Member) -> ReadMemberRecord {
    ReadMemberRecord {
        ring: ring(),
        member,
    }
}

fn listed(tree: &mut MemberRegistryTree, writes: &[(Member, u64)]) {
    let writes: Vec<_> = writes
        .iter()
        .map(|(member, lists)| (*member.as_bytes(), *lists))
        .collect();
    let items = tree.list_items(&writes).unwrap();
    tree.apply(&items).unwrap();
}

#[test]
fn present_and_absent_records_decode_under_the_served_root() {
    let mut tree = MemberRegistryTree::new().unwrap();
    listed(&mut tree, &[(member(4), 5), (member(9), 1)]);
    let root = current(&tree, 2);
    let present = read(member(4))
        .decode(root, response(&tree, &member(4), 2, None))
        .unwrap();
    assert_eq!(present.opening.lists(), 5);
    assert!(present.opening.is_present());
    assert!(present.sealed_key().is_none());
    let absent = read(member(7))
        .decode(root, response(&tree, &member(7), 2, None))
        .unwrap();
    assert_eq!(absent.opening.lists(), 0);
    // Owner tags hash the key, so the bracketing record is whichever sorts below.
    let target = *member(7).as_bytes();
    assert!(matches!(
        absent.opening,
        RecordOpening::Absent { low, .. } if low.member < target && target < low.next
    ));
}

#[test]
fn a_substituted_record_root_or_path_is_refused() {
    let mut tree = MemberRegistryTree::new().unwrap();
    listed(&mut tree, &[(member(4), 5)]);
    let root = current(&tree, 0);
    let mutations: [fn(&mut GetRingMemberRecordResponse); 6] = [
        |response| response.root.0[31] ^= 1,
        |response| response.next_index += 1,
        |response| response.root_index += 1,
        |response| response.path[0].0[31] ^= 1,
        |response| response.record.as_mut().unwrap().lists ^= 2,
        |response| response.index += 1,
    ];
    for mutate in mutations {
        let mut tampered = response(&tree, &member(4), 0, None);
        mutate(&mut tampered);
        assert!(matches!(
            read(member(4)).decode(root, tampered),
            Err(RingError::InvalidRecordOpening)
        ));
    }
    // An absent answer for a present member cannot bracket it.
    let mut wrong = response(&tree, &member(7), 0, None);
    wrong.low.as_mut().unwrap().next = Hash(*member(4).as_bytes());
    assert!(matches!(
        read(member(7)).decode(root, wrong),
        Err(RingError::InvalidRecordOpening)
    ));
}

#[test]
fn a_registered_key_opens_to_the_auditor_and_verifies_by_public_key() {
    let auditor = X25519Secret::new();
    let nullifier_key = NullifierKey::from_secret([7; 31]);
    let envelope = NullifierKeyEnvelope::new(&nullifier_key, &auditor.pubkey()).unwrap();
    let escrow_key = EscrowKey {
        nullifier_pk: &envelope.nullifier_pk,
        ciphertext: &envelope.sealed.ciphertext,
    }
    .hash()
    .unwrap();
    let mut tree = MemberRegistryTree::new().unwrap();
    let item = tree
        .register_item(member(4).as_bytes(), escrow_key)
        .unwrap();
    tree.apply(&[item]).unwrap();
    let root = current(&tree, 1);
    let read = read(member(4))
        .decode(root, response(&tree, &member(4), 1, Some(&envelope.sealed)))
        .unwrap();
    let entry = read.sealed_key().expect("a registered key");
    assert_eq!(
        entry.open(&auditor).unwrap().secret(),
        nullifier_key.secret()
    );
    assert!(entry
        .verify_nullifier_pubkey(&envelope.nullifier_pk)
        .is_ok());
    assert!(matches!(
        entry.verify_nullifier_pubkey(&[1; 32]),
        Err(RingError::InvalidRecordOpening)
    ));
    assert!(matches!(
        entry.open(&X25519Secret::new()),
        Err(RingError::Audit(_) | RingError::InvalidRecordOpening)
    ));
}

/// The plan reproduces the reference tree's witnesses from the indexer's openings alone.
#[test]
fn a_batch_plan_matches_the_reference_tree_through_inserts_and_rewrites() {
    let mut tree = MemberRegistryTree::new().unwrap();
    listed(&mut tree, &[(member(10), 1), (member(40), 1)]);
    let base = tree.clone();
    let writes = [
        MemberWrite::add(member(10), ListId::Block),
        MemberWrite::add(member(20), ListId::Allow),
        MemberWrite::remove(member(40), ListId::Allow),
        MemberWrite::add(member(50), ListId::Allow),
        MemberWrite::add(member(50), ListId::Frozen),
    ];
    let records: Vec<_> = [10, 20, 40, 50]
        .into_iter()
        .map(|byte| {
            read(member(byte))
                .decode(current(&base, 0), response(&base, &member(byte), 0, None))
                .unwrap()
        })
        .collect();
    let plan = BatchPlan::new(&tip(&base, 0), &writes, &records).unwrap();
    let expected = tree.apply(&plan.items).unwrap();
    assert_eq!(plan.new_root, tree.root());
    for (update, reference) in plan.updates.iter().zip(&expected) {
        assert_eq!(update.exists, reference.exists);
        assert_eq!(update.next, reference.next);
        assert_eq!(update.index, reference.index);
        assert_eq!(update.path, reference.path);
        if let Some(low) = &reference.low {
            assert_eq!(update.low_member, low.member);
            assert_eq!(update.low_index, low.index);
            assert_eq!(update.low_path, low.path);
        }
    }
    let lists = |byte| tree.find(member(byte).as_bytes()).unwrap().1.lists;
    assert_eq!(
        lists(10),
        ListSet::of(&[ListId::Allow, ListId::Block]).record_bits()
    );
    assert_eq!(lists(40), 0);
    assert_eq!(
        lists(50),
        ListSet::of(&[ListId::Allow, ListId::Frozen]).record_bits()
    );
    let body = plan.body(&tip(&base, 0)).unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&RingRequest(&body).body().unwrap()).unwrap();
    assert_eq!(json["circuitType"], "custom-ring-update-members");
    assert_eq!(json["itemCount"], 4);
    assert_eq!(json["items"].as_array().unwrap().len(), 16);
    assert!(json["items"][4].is_null());
    let inserted = plan
        .items
        .iter()
        .position(|item| item.member == *member(20).as_bytes())
        .unwrap();
    assert_eq!(json["items"][inserted]["exists"], false);
    assert_eq!(json["items"][inserted]["lists"], ListId::Allow.record_bit());
    assert_eq!(
        json["items"][inserted]["lowPath"].as_array().unwrap().len(),
        MEMBER_REGISTRY_HEIGHT
    );
}

#[test]
fn writes_that_change_nothing_or_conflict_are_refused() {
    let mut tree = MemberRegistryTree::new().unwrap();
    listed(&mut tree, &[(member(10), 1)]);
    let records = vec![read(member(10))
        .decode(current(&tree, 0), response(&tree, &member(10), 0, None))
        .unwrap()];
    let same = [MemberWrite::add(member(10), ListId::Allow)];
    assert!(matches!(
        BatchPlan::new(&tip(&tree, 0), &same, &records),
        Err(RingError::EmptyMemberBatch)
    ));
    let conflict = [
        MemberWrite::add(member(10), ListId::Block),
        MemberWrite::remove(member(10), ListId::Block),
    ];
    assert!(matches!(
        BatchPlan::new(&tip(&tree, 0), &conflict, &records),
        Err(RingError::ConflictingListWrite(ListId::Block))
    ));
}

#[test]
fn a_registration_inserts_or_rewrites_as_the_reference_tree_does() {
    let auditor = X25519Secret::new();
    let nullifier_key = NullifierKey::from_secret([7; 31]);
    let envelope = NullifierKeyEnvelope::new(&nullifier_key, &auditor.pubkey()).unwrap();
    let escrow_key = EscrowKey {
        nullifier_pk: &envelope.nullifier_pk,
        ciphertext: &envelope.sealed.ciphertext,
    }
    .hash()
    .unwrap();
    let secret = || Zeroizing::new(right_align(&nullifier_key.secret()));
    let mut tree = MemberRegistryTree::new().unwrap();
    listed(&mut tree, &[(member(3), 1), (member(12), 2)]);
    // A listed member keeps its lists.
    let listed_read = read(member(12))
        .decode(current(&tree, 0), response(&tree, &member(12), 0, None))
        .unwrap();
    let (body, item) = register(
        &envelope,
        auditor.pubkey(),
        secret(),
        &tip(&tree, 0),
        &listed_read.opening,
    )
    .unwrap();
    let expected = tree
        .register_item(member(12).as_bytes(), escrow_key)
        .unwrap();
    assert_eq!(item, expected);
    assert_eq!(item.lists, 2);
    tree.apply(&[item]).unwrap();
    assert_eq!(body.registry_new_root, tree.root());
    assert!(body.update.exists);
    // An absent opening names no member, the registration takes the member's own record.
    let absent = read(member(9))
        .decode(current(&tree, 1), response(&tree, &member(9), 1, None))
        .unwrap();
    assert!(matches!(
        register(
            &envelope,
            auditor.pubkey(),
            secret(),
            &tip(&tree, 1),
            &absent.opening,
        ),
        Err(RingError::InvalidRecordOpening)
    ));
}

#[test]
fn a_second_registration_is_refused_before_proving() {
    let auditor = X25519Secret::new();
    let nullifier_key = NullifierKey::from_secret([7; 31]);
    let envelope = NullifierKeyEnvelope::new(&nullifier_key, &auditor.pubkey()).unwrap();
    let mut tree = MemberRegistryTree::new().unwrap();
    let item = tree.register_item(member(4).as_bytes(), [9; 32]).unwrap();
    tree.apply(&[item]).unwrap();
    let read = read(member(4))
        .decode(current(&tree, 1), response(&tree, &member(4), 1, None))
        .unwrap();
    assert!(matches!(
        register(
            &envelope,
            auditor.pubkey(),
            Zeroizing::new([0; 32]),
            &tip(&tree, 1),
            &read.opening,
        ),
        Err(RingError::KeyAlreadyRegistered { .. })
    ));
}

#[test]
fn the_update_instruction_lists_the_signers_after_the_registry() {
    let proven = ProvenMemberUpdate {
        ring: ring(),
        signers: vec![
            Address::new_from_array([1; 32]),
            Address::new_from_array([2; 32]),
        ],
        old_root: RegistryBinding {
            root_index: 3,
            root: [4; 32],
        },
        new_root: [5; 32],
        items: vec![MemberUpdate {
            member: *member(4).as_bytes(),
            lists: 1,
            index: 1,
            ..MemberUpdate::default()
        }],
        proof: CustomRingProof {
            groth16: custom_ring_interface::PlainGroth16Proof {
                proof_a: [1; 32],
                proof_b: [2; 64],
                proof_c: [3; 32],
            },
            commitment: [4; 32],
            commitment_pok: [5; 32],
        },
    };
    let instruction = proven.instruction().unwrap();
    assert_eq!(instruction.data[0], tag::UPDATE_MEMBERS);
    assert_eq!(instruction.accounts.len(), 4);
    assert_eq!(instruction.accounts[0].pubkey, ring().config_pda());
    assert!(instruction.accounts[1].is_writable);
    assert_eq!(
        instruction.accounts[1].pubkey,
        ring().member_registry_root_pda()
    );
    assert!(instruction.accounts[2].is_signer && instruction.accounts[3].is_signer);
    let decoded: UpdateMembersIxData = wincode::deserialize_exact(&instruction.data[1..]).unwrap();
    assert_eq!(decoded.old_root_index, 3);
    assert_eq!(decoded.items.len(), 1);
    let _ = MemberRecord::SENTINEL;
}
