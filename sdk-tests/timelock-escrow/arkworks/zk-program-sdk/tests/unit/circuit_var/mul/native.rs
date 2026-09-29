use ark_bn254::Fr;
use zk_program_sdk::{
    circuit::{constant, value, zero, CircuitVar, Field},
    conversion::{self, Allocator, ProofInput},
    CircuitError,
};

use super::{
    fixtures::{every_form, every_form_name, RULE_BROKEN},
    vectors::{INVALID, NON_CANONICAL, VALID},
};
use crate::harness::{
    field::{be_bytes, canonical, field, integer, modulus, MODULUS_MINUS_1},
    fixture::{expected, native_circuit, outcome, per_vector, Fixture, Native, Refusal, Visit},
};

struct NativeProduct;

impl Visit<CircuitVar> for NativeProduct {
    type Output = (String, Result<Field, Refusal>);

    fn visit<F: Fixture<CircuitVar>>(&self, fixture: &F) -> Self::Output {
        let product = F::computed(&native_circuit(fixture).expect("native instantiation"));
        (format!("{product:?}"), outcome(value(&product)))
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
fn the_native_product_is_field_multiplication_modulo_p_in_every_form() {
    let field_products: Vec<_> = VALID
        .iter()
        .map(|vector| {
            let (left, right, _) = vector.fields();
            left * right
        })
        .collect();
    assert_eq!(
        (
            field_products,
            per_vector(&VALID, |vector| every_form(&NativeProduct, vector.fields()))
        ),
        (
            VALID.iter().map(|vector| field(vector.product)).collect(),
            expected(&VALID, &every_form_name(), |vector, _| {
                let product = field(vector.product);
                (
                    format!("CircuitVar::constant({})", Fr::from(product)),
                    Ok(product),
                )
            })
        )
    );
}

#[test]
fn constant_multiplication_is_a_commutative_ring_product_over_addition() {
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
    let minus_one = field(MODULUS_MINUS_1);
    assert_eq!(
        (
            values(pairs().map(|(a, b)| a * b).collect()),
            values(triples().map(|(a, b, c)| (a * b) * c).collect()),
            values(triples().map(|(a, b, c)| a * (b + c)).collect()),
            values(operands.iter().map(|a| a * Field::from(1u64)).collect()),
            values(operands.iter().map(|a| a * zero()).collect()),
            values(operands.iter().map(|a| a * minus_one).collect()),
        ),
        (
            values(pairs().map(|(a, b)| b * a).collect()),
            values(triples().map(|(a, b, c)| a * (b * c)).collect()),
            values(triples().map(|(a, b, c)| a * b + a * c).collect()),
            values(operands.clone()),
            vec![Field::from(0u64); operands.len()],
            values(operands.iter().map(|a| -a).collect()),
        )
    );
}

#[test]
fn a_product_of_p_is_refused_before_it_reaches_the_circuit() {
    let (left, right) = (field(NON_CANONICAL.left), field(NON_CANONICAL.right));
    let bytes = be_bytes(NON_CANONICAL.product);
    let refusal = |error: CircuitError| (error.name(), error.to_string());
    assert_eq!(
        (
            integer(NON_CANONICAL.product) == modulus(),
            canonical(NON_CANONICAL.product),
            left * right,
            conversion::field(&bytes, "product").map_err(refusal),
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
                "product is too large for a circuit value".to_string()
            )),
            Err((
                "CircuitError.BytesTooLarge",
                "32-byte input is too large for a circuit value".to_string()
            )),
        )
    );
}
