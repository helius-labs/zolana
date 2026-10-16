use super::{
    fixtures::{HashBytes, RULE_BROKEN},
    vectors::native_hash,
};
use crate::harness::fixture::{assignment, check_constraints, check_tampered, exported, native};
use ark_bn254::Fr;
use proptest::prelude::*;
use zolana_program::Bytes;
proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]
    #[test]
    fn random_multichunk_hashes_match_native_and_reject_changed_outputs(bytes in any::<[u8;63]>()) {
        let fixture = HashBytes { bytes: Bytes(bytes), hash: native_hash(&bytes) };
        prop_assert_eq!(native(&fixture),Ok(()));
        prop_assert_eq!(check_constraints(&fixture), Ok(exported::<HashBytes<63>>().header.constraints));
        prop_assert_eq!(exported::<HashBytes<63>>().first_unsatisfied(&assignment(&fixture)),None);
        let wrong = (Fr::from(fixture.hash)+Fr::from(1u64)).into();
        prop_assert_eq!(native(&HashBytes { hash: wrong, ..fixture }), Err(RULE_BROKEN));
        prop_assert!(check_tampered(&fixture,568,wrong).is_err());
    }
}
