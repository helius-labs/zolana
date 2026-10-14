use ark_bn254::Fr;
use zolana_program::{
    circuit::{constant, value, zero, CircuitVar, Field},
    conversion::{self, Allocator, ProofInput},
    CircuitError,
};

use super::{
    fixtures::{every_form, every_form_name, RULE_BROKEN},
    vectors::{INVALID, NON_CANONICAL, VALID},
};
use crate::harness::{
    field::{be_bytes, canonical, field, integer, modulus},
    fixture::{expected, native_circuit, outcome, per_vector, Fixture, Native, Refusal, Visit},
};

struct NativeSum;

impl Visit<CircuitVar> for NativeSum {
    type Output = (String, Result<Field, Refusal>);

    fn visit<F: Fixture<CircuitVar>>(&self, fixture: &F) -> Self::Output {
        let sum = F::computed(&native_circuit(fixture).expect("native instantiation"));
        (format!("{sum:?}"), outcome(value(&sum)))
    }
}

#[test]
fn every_valid_vector_holds_natively_in_every_form() {
    assert_eq!(
        per_vector(&VALID, |vector| every_form(&Native, vector.fields())),
        expected(&VALID, &every_form_name(), |_, _| Ok(()))
    );
}

#[test]
fn every_invalid_vector_breaks_exactly_the_fixture_rule_natively() {
    assert_eq!(
        per_vector(&INVALID, |vector| every_form(&Native, vector.fields())),
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
            per_vector(&VALID, |vector| every_form(&NativeSum, vector.fields()))
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
