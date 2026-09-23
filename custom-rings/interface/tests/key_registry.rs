use custom_ring_interface::{
    KeyRegistryInsert, KeyRegistryVerifyError, KEY_REGISTRY_CAPACITY, KEY_REGISTRY_HEIGHT,
};
use zolana_hasher::primitives::{right_align, BN254_SCALAR_MODULUS_BE};

#[test]
fn registration_checks_both_indices_and_strict_member_range() {
    let zero = [0; 32];
    let member = right_align(&[1]);
    let next = right_align(&[2]);
    let proof = [[0; 32]; KEY_REGISTRY_HEIGHT];
    let mut insertion = KeyRegistryInsert {
        root: &zero,
        append_index: 1,
        member: &member,
        key: &zero,
        low_member: &zero,
        low_next: &next,
        low_key: &zero,
        low_index: 0,
        low_proof: &proof,
        new_proof: &proof,
    };
    insertion.low_index = KEY_REGISTRY_CAPACITY;
    assert_eq!(insertion.verify(), Err(KeyRegistryVerifyError::OutOfRange));
    insertion.low_index = 0;
    for index in [0, KEY_REGISTRY_CAPACITY, u64::MAX] {
        insertion.append_index = index;
        assert_eq!(insertion.verify(), Err(KeyRegistryVerifyError::OutOfRange));
    }
    insertion.append_index = 1;
    insertion.member = &zero;
    assert_eq!(insertion.verify(), Err(KeyRegistryVerifyError::OutOfRange));
    insertion.member = &member;
    insertion.key = &BN254_SCALAR_MODULUS_BE;
    assert_eq!(insertion.verify(), Err(KeyRegistryVerifyError::OutOfRange));
}
