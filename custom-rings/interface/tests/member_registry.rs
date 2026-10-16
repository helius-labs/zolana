use custom_ring_interface::{
    MemberOpening, MemberRecord, MemberRegistryVerifyError, MerklePath, FIELD_MAX,
    MEMBER_REGISTRY_CAPACITY, MEMBER_REGISTRY_EMPTY_ROOT, MEMBER_REGISTRY_HEIGHT,
};
use zolana_hasher::{primitives::right_align, Hasher, Poseidon};

fn zero_path() -> Vec<[u8; 32]> {
    Poseidon::zero_bytes()[..MEMBER_REGISTRY_HEIGHT].to_vec()
}

#[test]
fn an_absent_member_opens_under_the_sentinel_of_the_empty_registry() {
    let siblings = zero_path();
    let path = MerklePath {
        index: 0,
        siblings: &siblings,
    };
    let member = right_align(&[7]);
    let opening = MemberOpening::Absent {
        low: MemberRecord::SENTINEL,
        path,
    };
    assert_eq!(
        opening.verify(&MEMBER_REGISTRY_EMPTY_ROOT, &member),
        Ok((0, [0; 32]))
    );
    assert_eq!(
        opening.verify(&MEMBER_REGISTRY_EMPTY_ROOT, &[0; 32]),
        Err(MemberRegistryVerifyError::NotBracketed)
    );
    assert_eq!(
        opening.verify(&MEMBER_REGISTRY_EMPTY_ROOT, &FIELD_MAX),
        Err(MemberRegistryVerifyError::NotBracketed)
    );
    assert_eq!(
        opening.verify(&[1; 32], &member),
        Err(MemberRegistryVerifyError::RootMismatch)
    );
}

#[test]
fn a_present_member_opens_to_its_lists_and_key() {
    let member = right_align(&[7]);
    let record = MemberRecord {
        member,
        next: FIELD_MAX,
        lists: 0b101,
        escrow_key: right_align(&[9]),
    };
    // Leaf 1 beside the sentinel, every other sibling empty.
    let sentinel = MemberRecord::SENTINEL.hash().unwrap();
    let mut siblings = zero_path();
    siblings[0] = sentinel;
    let path = MerklePath {
        index: 1,
        siblings: &siblings,
    };
    let root = path.root_of(record.hash().unwrap()).unwrap();
    let opening = MemberOpening::Present { record, path };
    assert_eq!(
        opening.verify(&root, &member),
        Ok((0b101, right_align(&[9])))
    );
    assert_eq!(
        opening.verify(&root, &right_align(&[8])),
        Err(MemberRegistryVerifyError::NotBracketed)
    );
}

#[test]
fn paths_check_their_length_and_index_range() {
    let short = zero_path();
    let path = MerklePath {
        index: 0,
        siblings: &short[..MEMBER_REGISTRY_HEIGHT - 1],
    };
    assert_eq!(
        path.root_of([0; 32]),
        Err(MemberRegistryVerifyError::PathLength)
    );
    let siblings = zero_path();
    let path = MerklePath {
        index: MEMBER_REGISTRY_CAPACITY,
        siblings: &siblings,
    };
    assert_eq!(
        path.root_of([0; 32]),
        Err(MemberRegistryVerifyError::OutOfRange)
    );
}
