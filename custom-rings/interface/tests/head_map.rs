use custom_ring_interface::{
    HeadMapInsert, HeadMapVerifyError, HEAD_MAP_CAPACITY, HEAD_MAP_HEIGHT,
};
use zolana_hasher::primitives::{right_align, BN254_SCALAR_MODULUS_BE};

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
