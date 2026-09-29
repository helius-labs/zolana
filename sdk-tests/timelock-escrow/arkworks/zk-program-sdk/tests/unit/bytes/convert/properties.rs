use super::{
    fixtures::{pack_fixture, split_fixture, PACK_BROKEN, SPLIT_BROKEN},
    vectors::Pair,
};
use crate::{
    bytes::support::packed,
    harness::fixture::{assignment, check_constraints, check_tampered, exported, native},
};
use proptest::prelude::*;
use zk_program_sdk::circuit::Field;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn random_31_byte_pack_and_split_agree_and_reject_changed_claims(bytes in any::<[u8;31]>(), index in 0usize..31) {
        let pair = Pair { value: packed(&bytes), bytes: bytes.to_vec() };
        let pack = pack_fixture::<31,0>(&pair);
        let split = split_fixture::<31,0>(&pair);
        prop_assert_eq!(native(&pack), Ok(()));
        prop_assert_eq!(native(&split), Ok(()));
        prop_assert_eq!(check_constraints(&pack), Ok(280));
        prop_assert_eq!(check_constraints(&split), Ok(280));
        prop_assert_eq!(exported::<super::fixtures::Pack<31,0>>().first_unsatisfied(&assignment(&pack)), None);
        prop_assert_eq!(exported::<super::fixtures::Split<31,0>>().first_unsatisfied(&assignment(&split)), None);
        let wrong = Field::from(ark_bn254::Fr::from(pair.value) + ark_bn254::Fr::from(1u64));
        prop_assert_eq!(native(&super::fixtures::Pack { packed: wrong, ..pack }), Err(PACK_BROKEN));
        prop_assert!(check_tampered(&pack, 280, wrong).is_err());
        let mut dishonest = split;
        let claim = dishonest.bytes.get_mut(index).expect("claim index");
        *claim = Field::from(ark_bn254::Fr::from(*claim) + ark_bn254::Fr::from(1u64));
        prop_assert_eq!(native(&dishonest), Err(SPLIT_BROKEN));
        prop_assert!(check_tampered(&split, 2+index, *dishonest.bytes.get(index).expect("claim index")).is_err());
    }
}
