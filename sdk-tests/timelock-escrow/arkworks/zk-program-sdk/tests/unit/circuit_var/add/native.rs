use std::fmt::Debug;

use ark_bn254::Fr;
use zk_program_sdk::{
    circuit::{constant, value, zero, CircuitVar, Constraints, Field},
    conversion::{self, Allocator, ProofInput},
    CircuitError, ZkCircuit,
};

use super::{
    fixtures::{
        every_form, every_form_name, expected, outcome, per_vector, Operands, Refusal, Visit,
        RULE_BROKEN,
    },
    vectors::{INVALID, NON_CANONICAL, VALID},
};
use crate::harness::field::{be_bytes, canonical, field, integer, modulus};

struct Native;

impl Visit for Native {
    type Output = Result<(), Refusal>;

    fn visit<F>(&self, fixture: F) -> Self::Output
    where
        F: ZkCircuit + Copy + Debug,
        F::Circuit: Operands,
    {
        outcome(
            fixture
                .instantiate(&Allocator::native())
                .and_then(|circuit| circuit.constraints()),
        )
    }
}

struct NativeSum;

impl Visit for NativeSum {
    type Output = (String, Result<Field, Refusal>);

    fn visit<F>(&self, fixture: F) -> Self::Output
    where
        F: ZkCircuit + Copy + Debug,
        F::Circuit: Operands,
    {
        let sum = fixture
            .instantiate(&Allocator::native())
            .expect("native instantiation")
            .form();
        (format!("{sum:?}"), outcome(value(&sum)))
    }
}

#[test]
fn every_valid_vector_holds_natively_in_every_form() {
    assert_eq!(
        per_vector(&VALID, |fields| every_form(&Native, fields)),
        expected(&VALID, &every_form_name(), |_, _| Ok(()))
    );
}

#[test]
fn every_invalid_vector_breaks_exactly_the_fixture_rule_natively() {
    assert_eq!(
        per_vector(&INVALID, |fields| every_form(&Native, fields)),
        expected(&INVALID, &every_form_name(), |_, _| Err(RULE_BROKEN))
    );
}

#[test]
fn the_native_sum_is_field_addition_modulo_p_in_every_form() {
    let field_sums: Vec<_> = VALID
        .iter()
        .map(|vector| {
            let (left, right, _) = vector.fields();
            left + right
        })
        .collect();
    assert_eq!(
        (
            field_sums,
            per_vector(&VALID, |fields| every_form(&NativeSum, fields))
        ),
        (
            VALID.iter().map(|vector| field(vector.sum)).collect(),
            expected(&VALID, &every_form_name(), |vector, _| {
                let sum = field(vector.sum);
                (format!("CircuitVar::constant({})", Fr::from(sum)), Ok(sum))
            })
        )
    );
}

#[test]
fn constant_addition_is_commutative_and_associative_with_identity_and_inverse() {
    let operands: Vec<CircuitVar> = VALID
        .iter()
        .flat_map(|vector| [vector.left, vector.right])
        .map(|decimal| constant(field(decimal)))
        .collect();
    let values = |vars: Vec<CircuitVar>| -> Vec<Field> {
        vars.iter()
            .map(|var| value(var).expect("constant"))
            .collect()
    };
    let pairs = || {
        operands
            .iter()
            .flat_map(|a| operands.iter().map(move |b| (a, b)))
    };
    let triples = || pairs().flat_map(|(a, b)| operands.iter().map(move |c| (a, b, c)));
    assert_eq!(
        (
            values(pairs().map(|(a, b)| a + b).collect()),
            values(triples().map(|(a, b, c)| (a + b) + c).collect()),
            values(operands.iter().map(|a| a + zero()).collect()),
            values(operands.iter().map(|a| a + -a).collect()),
        ),
        (
            values(pairs().map(|(a, b)| b + a).collect()),
            values(triples().map(|(a, b, c)| a + (b + c)).collect()),
            values(operands.clone()),
            vec![Field::from(0u64); operands.len()],
        )
    );
}

#[test]
fn a_sum_of_p_is_refused_before_it_reaches_the_circuit() {
    let (left, right) = (field(NON_CANONICAL.left), field(NON_CANONICAL.right));
    let bytes = be_bytes(NON_CANONICAL.sum);
    let refusal = |error: CircuitError| (error.name(), error.to_string());
    assert_eq!(
        (
            integer(NON_CANONICAL.sum) == modulus(),
            canonical(NON_CANONICAL.sum),
            left + right,
            conversion::field(&bytes, "sum").map_err(refusal),
            bytes
                .instantiate(&Allocator::native())
                .map(|_| ())
                .map_err(refusal),
        ),
        (
            true,
            None,
            Field::from(0u64),
            Err((
                "CircuitError.BytesTooLarge",
                "sum is too large for a circuit value".to_string()
            )),
            Err((
                "CircuitError.BytesTooLarge",
                "32-byte input is too large for a circuit value".to_string()
            )),
        )
    );
}
