use std::fmt::Debug;

use ark_bn254::Fr;
use ark_ff::One;
use proptest::prelude::*;
use zk_program_sdk::{
    circuit::{value, Constraints, Field},
    conversion::Allocator,
    testing::{check_tampered, Tamper},
    ZkCircuit,
};

use super::fixtures::{
    every_form, every_form_name, variable_form_names, variable_forms, Operands, Variables, Visit,
    RULE,
};
use crate::harness::{
    field::random,
    iden3::{read_r1cs, read_wtns},
};

fn arbitrary_field() -> impl Strategy<Value = Field> {
    any::<[u8; 32]>().prop_map(random)
}

fn every<T: Clone>(forms: Vec<&'static str>, value: T) -> Vec<(&'static str, T)> {
    forms
        .into_iter()
        .map(|form| (form, value.clone()))
        .collect()
}

struct BrokenRule;

impl Visit for BrokenRule {
    type Output = Option<&'static str>;

    fn visit<F>(&self, fixture: F) -> Self::Output
    where
        F: ZkCircuit + Copy + Debug,
        F::Circuit: Operands,
    {
        fixture
            .instantiate(&Allocator::native())
            .and_then(|circuit| circuit.constraints())
            .err()
            .map(|error| error.broken_rule())
            .unwrap_or(None)
    }
}

struct NativeSum;

impl Visit for NativeSum {
    type Output = Field;

    fn visit<F>(&self, fixture: F) -> Field
    where
        F: ZkCircuit + Copy + Debug,
        F::Circuit: Operands,
    {
        let circuit = fixture
            .instantiate(&Allocator::native())
            .expect("native instantiation");
        value(&circuit.form()).expect("constant sum")
    }
}

struct CheckConstraints;

impl Visit for CheckConstraints {
    type Output = Option<usize>;

    fn visit<F>(&self, fixture: F) -> Option<usize>
    where
        F: ZkCircuit + Copy + Debug,
        F::Circuit: Operands,
    {
        fixture.check_constraints().ok()
    }
}

struct TamperSum(Field);

impl Visit for TamperSum {
    type Output = Option<&'static str>;

    fn visit<F>(&self, fixture: F) -> Option<&'static str>
    where
        F: ZkCircuit + Copy + Debug,
        F::Circuit: Operands,
    {
        let variables = read_wtns(&fixture.export_assignment().expect("assignment")).len();
        check_tampered(
            &fixture,
            Tamper::PrivateVariable {
                index: variables - 2,
                value: self.0,
            },
        )
        .err()
        .and_then(|error| error.broken_rule())
    }
}

proptest! {
    #[test]
    fn natively_every_form_holds_exactly_when_the_sum_is_left_plus_right(
        left in arbitrary_field(),
        right in arbitrary_field(),
        claimed in arbitrary_field(),
        honest in any::<bool>(),
    ) {
        let sum = if honest { left + right } else { claimed };
        let broken = (sum != left + right).then_some(RULE);
        prop_assert_eq!(
            every_form(&BrokenRule, (left, right, sum)),
            every(every_form_name(), broken)
        );
    }

    #[test]
    fn check_constraints_counts_one_constraint_for_every_valid_triple(
        left in arbitrary_field(),
        right in arbitrary_field(),
    ) {
        prop_assert_eq!(
            variable_forms(&CheckConstraints, (left, right, left + right)),
            every(variable_form_names(), Some(1))
        );
    }

    #[test]
    fn a_wrong_sum_is_refused_natively_and_in_r1cs(
        left in arbitrary_field(),
        right in arbitrary_field(),
        offset in arbitrary_field().prop_filter("a wrong sum", |offset| *offset != Field::from(0u64)),
    ) {
        let wrong = left + right + offset;
        let r1cs = read_r1cs(&Variables::<3>::export_r1cs().expect("r1cs export"));
        let witness = [Fr::one(), left.into(), right.into(), wrong.into()];
        prop_assert_eq!(
            (
                every_form(&BrokenRule, (left, right, wrong)),
                every_form(&TamperSum(wrong), (left, right, left + right)),
                r1cs.first_unsatisfied(&witness),
            ),
            (
                every(every_form_name(), Some(RULE)),
                every(every_form_name(), Some(RULE)),
                Some(0),
            )
        );
    }

    #[test]
    fn every_form_gives_the_same_native_sum(
        left in arbitrary_field(),
        right in arbitrary_field(),
    ) {
        prop_assert_eq!(
            every_form(&NativeSum, (left, right, left + right)),
            every(every_form_name(), left + right)
        );
    }
}
