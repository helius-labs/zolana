use ark_bn254::Fr;
use ark_ff::One;
use proptest::prelude::*;
use zolana_program::{
    circuit::{value, CircuitVar, Field},
    testing::{check_tampered, Tamper},
    ZkCircuit,
};

use super::fixtures::{
    claimed_wire, every_form, every_form_name, variable_form_names, variable_forms, Variables,
    RULE, RULE_BROKEN,
};
use crate::harness::{
    field::random,
    fixture::{assignment, each, native_circuit, Fixture, Native, Visit},
    iden3::read_r1cs,
};

fn arbitrary_field() -> impl Strategy<Value = Field> {
    any::<[u8; 32]>().prop_map(random)
}

struct NativeProduct;

impl Visit<CircuitVar> for NativeProduct {
    type Output = Field;

    fn visit<F: Fixture<CircuitVar>>(&self, fixture: &F) -> Field {
        let circuit = native_circuit(fixture).expect("native instantiation");
        value(&F::computed(&circuit)).expect("constant product")
    }
}

struct CheckConstraints;

impl<C> Visit<C> for CheckConstraints {
    type Output = Option<usize>;

    fn visit<F: Fixture<C>>(&self, fixture: &F) -> Option<usize> {
        fixture.check_constraints().ok()
    }
}

struct TamperProduct(Field);

impl<C> Visit<C> for TamperProduct {
    type Output = Option<&'static str>;

    fn visit<F: Fixture<C>>(&self, fixture: &F) -> Option<&'static str> {
        let wire = claimed_wire(assignment(fixture).len());
        check_tampered(
            fixture,
            Tamper::PrivateVariable {
                index: wire - 1,
                value: self.0,
            },
        )
        .err()
        .and_then(|error| error.broken_rule())
    }
}

proptest! {
    #[test]
    fn natively_every_form_holds_exactly_when_the_product_is_left_times_right(
        left in arbitrary_field(),
        right in arbitrary_field(),
        claimed in arbitrary_field(),
        honest in any::<bool>(),
    ) {
        let product = if honest { left * right } else { claimed };
        let expected = if product == left * right { Ok(()) } else { Err(RULE_BROKEN) };
        prop_assert_eq!(
            every_form(&Native, (left, right, product)),
            each(&every_form_name(), expected)
        );
    }

    #[test]
    fn check_constraints_counts_two_constraints_for_every_valid_triple(
        left in arbitrary_field(),
        right in arbitrary_field(),
    ) {
        prop_assert_eq!(
            variable_forms(&CheckConstraints, (left, right, left * right)),
            each(&variable_form_names(), Some(2))
        );
    }

    #[test]
    fn a_wrong_product_is_refused_natively_and_in_r1cs(
        left in arbitrary_field(),
        right in arbitrary_field(),
        offset in arbitrary_field().prop_filter("a wrong product", |offset| *offset != Field::from(0u64)),
        witness in arbitrary_field(),
    ) {
        let wrong = left * right + offset;
        let r1cs = read_r1cs(&Variables::<3>::export_r1cs().expect("r1cs export"));
        let assignment = [Fr::one(), left.into(), right.into(), wrong.into(), witness.into()];
        prop_assert_eq!(
            (
                every_form(&Native, (left, right, wrong)),
                every_form(&TamperProduct(wrong), (left, right, left * right)),
                r1cs.first_unsatisfied(&assignment).is_some(),
            ),
            (
                each(&every_form_name(), Err(RULE_BROKEN)),
                each(&every_form_name(), Some(RULE)),
                true,
            )
        );
    }

    #[test]
    fn every_form_gives_the_same_native_product(
        left in arbitrary_field(),
        right in arbitrary_field(),
    ) {
        prop_assert_eq!(
            every_form(&NativeProduct, (left, right, left * right)),
            each(&every_form_name(), left * right)
        );
    }
}
