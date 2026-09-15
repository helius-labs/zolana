use custom_ring_interface::{
    HeadMapInsert, HeadMapTransfer, HeadMapVerifyError, HEAD_MAP_CAPACITY, HEAD_MAP_HEIGHT,
};
use zolana_hasher::primitives::{right_align, BN254_SCALAR_MODULUS_BE};

#[test]
fn indexed_proofs_reject_truncated_indices_and_noncanonical_fields() {
    let zero = [0; 32];
    let member = right_align(&[1]);
    let next = right_align(&[2]);
    let proof = [[0; 32]; HEAD_MAP_HEIGHT];
    let mut transfer = HeadMapTransfer {
        root: &zero,
        member: &member,
        next: &next,
        spent: &zero,
        successor: &zero,
        index: 1,
        proof: &proof,
    };
    for index in [0, HEAD_MAP_CAPACITY, HEAD_MAP_CAPACITY + 1, u64::MAX] {
        transfer.index = index;
        assert_eq!(transfer.verify(), Err(HeadMapVerifyError::OutOfRange));
    }
    transfer.index = 1;
    transfer.member = &BN254_SCALAR_MODULUS_BE;
    assert_eq!(transfer.verify(), Err(HeadMapVerifyError::OutOfRange));
    transfer.member = &member;
    transfer.next = &member;
    assert_eq!(transfer.verify(), Err(HeadMapVerifyError::OutOfRange));
    transfer.next = &next;
    let mut bad_proof = proof;
    bad_proof[9] = BN254_SCALAR_MODULUS_BE;
    transfer.proof = &bad_proof;
    assert_eq!(transfer.verify(), Err(HeadMapVerifyError::OutOfRange));
}

#[test]
fn registration_checks_both_indices_and_strict_member_range() {
    let zero = [0; 32];
    let member = right_align(&[1]);
    let next = right_align(&[2]);
    let proof = [[0; 32]; HEAD_MAP_HEIGHT];
    let mut insertion = HeadMapInsert {
        root: &zero,
        append_index: 1,
        member: &member,
        genesis: &zero,
        low_member: &zero,
        low_next: &next,
        low_nullifier: &zero,
        low_index: 0,
        low_proof: &proof,
        new_proof: &proof,
    };
    insertion.low_index = HEAD_MAP_CAPACITY;
    assert_eq!(insertion.verify(), Err(HeadMapVerifyError::OutOfRange));
    insertion.low_index = 0;
    for index in [0, HEAD_MAP_CAPACITY, u64::MAX] {
        insertion.append_index = index;
        assert_eq!(insertion.verify(), Err(HeadMapVerifyError::OutOfRange));
    }
    insertion.append_index = 1;
    insertion.member = &zero;
    assert_eq!(insertion.verify(), Err(HeadMapVerifyError::OutOfRange));
    insertion.member = &member;
    insertion.genesis = &BN254_SCALAR_MODULUS_BE;
    assert_eq!(insertion.verify(), Err(HeadMapVerifyError::OutOfRange));
}
