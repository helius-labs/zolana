use super::fixtures::{is_in_fixture, AssertIn, IsIn};
use crate::{
    gadgets::reference::arbitrary_field,
    harness::fixture::{assignment, check_constraints, check_tampered, exported, native},
};
use proptest::prelude::*;
use zolana_program::circuit::Field;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]
    #[test]
    fn membership_matches_slice_contains_for_random_sets(
        set in prop::array::uniform3(arbitrary_field()), outsider in arbitrary_field(), index in 0usize..4,
    ) {
        let value = set.get(index).copied().unwrap_or(outsider);
        let member = set.contains(&value);
        let honest = is_in_fixture(value, set, member);
        prop_assert_eq!(native(&honest), Ok(()));
        prop_assert_eq!(check_constraints(&honest), Ok(5));
        prop_assert_eq!(exported::<IsIn<3>>().first_unsatisfied(&assignment(&honest)), None);
        prop_assert!(check_tampered(&honest, 5, Field::from(!member)).is_err());
        prop_assert!(native(&is_in_fixture(value, set, !member)).is_err());
        prop_assert_eq!(native(&AssertIn { value, set }).is_ok(), member);
        if member { prop_assert_eq!(check_constraints(&AssertIn { value, set }), Ok(3)); }
    }
}
