use super::fixtures::{decoded, selected};
use crate::{
    gadgets::reference::arbitrary_field,
    harness::{
        field::field,
        fixture::{assignment, check_constraints, check_tampered, exported, native},
    },
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn random_items_select_the_index_and_refuse_every_changed_claim(
        items in prop::array::uniform3(arbitrary_field()), index in 0usize..3,
        offset in arbitrary_field().prop_filter("nonzero offset", |value| *value != field("0")),
    ) {
        let fixture = selected(items, index);
        prop_assert_eq!(native(&fixture), Ok(()));
        prop_assert_eq!(check_constraints(&fixture), Ok(10));
        prop_assert_eq!(exported::<super::fixtures::SelectIndex<3>>().first_unsatisfied(&assignment(&fixture)), None);
        prop_assert!(check_tampered(&fixture, 5, fixture.selected + offset).is_err());
        let mut wrong = fixture;
        wrong.selected = wrong.selected + offset;
        prop_assert!(native(&wrong).is_err());
        let flags = decoded::<3>(index);
        prop_assert_eq!(check_constraints(&flags), Ok(10));
        prop_assert!(check_tampered(&flags, index + 2, field("2")).is_err());
    }
}
