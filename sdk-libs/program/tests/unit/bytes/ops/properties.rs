use super::fixtures::*;
use crate::{
    bytes::support::fields,
    harness::fixture::{assignment, check_constraints, check_tampered, exported, native},
};
use proptest::prelude::*;
use zolana_program::{circuit::Field, Bytes};
proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn random_byte_arrays_obey_assert_and_select_relations(left in any::<[u8;32]>(), other in any::<[u8;32]>(), equal in any::<bool>(), condition in any::<bool>(), changed in 0usize..32) {
        let right=if equal {left}else{other};
        let equal=left==right;
        prop_assert_eq!(native(&AssertEqual {left:Bytes(left),right:Bytes(right)}),if equal {Ok(())}else{Err(EQUAL_BROKEN)});
        prop_assert_eq!(native(&AssertNotEqual {left:Bytes(left),right:Bytes(right)}),if equal {Err(NOT_EQUAL_BROKEN)}else{Ok(())});
        prop_assert_eq!(native(&AssertEqualIf {left:Bytes(left),right:Bytes(right),condition}),if !condition || equal {Ok(())}else{Err(EQUAL_IF_BROKEN)});
        let equality=IsEqual {left:Bytes(left),right:Bytes(right),claimed:equal};
        prop_assert_eq!(native(&equality),Ok(()));
        prop_assert_eq!(check_constraints(&equality),Ok(exported::<IsEqual<32>>().header.constraints));
        prop_assert!(check_tampered(&equality,577,Field::from(!equal)).is_err());
        let selected=if condition {left}else{right};
        let fixture=Selected {condition,if_true:Bytes(left),if_false:Bytes(right),selected:fields(&selected)};
        prop_assert_eq!(native(&fixture),Ok(()));
        prop_assert_eq!(check_constraints(&fixture),Ok(exported::<Selected<32>>().header.constraints));
        prop_assert_eq!(exported::<Selected<32>>().first_unsatisfied(&assignment(&fixture)),None);
        let wrong=Field::from(selected.get(changed).expect("byte").wrapping_add(1));
        prop_assert!(check_tampered(&fixture,578+changed,wrong).is_err());
    }
}
