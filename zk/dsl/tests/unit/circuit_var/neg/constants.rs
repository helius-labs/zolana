use ark_bn254::Fr;
use ark_ff::One;
use proptest::prelude::*;
use zolana_program::{
    circuit::{constant, value, zero, Field},
    ProverError, ZkCircuit,
};

use super::{
    fixtures::{read, EqualsSeven, ReadsValue, FILE, RULE},
    vectors::VALID,
};
use crate::harness::{
    field::{field, random, MODULUS_MINUS_1},
    fixture::{check_constraints, exported, native, native_circuit, outcome, rule_broken, Refusal},
    iden3::{R1cs, R1csHeader},
};

const READS_VARIABLE_VALUE: &str = "CircuitError.ReadsVariableValue";

proptest! {
    #[test]
    fn generated_constants_round_trip_with_zero_and_keep_their_representation(
        x in any::<[u8; 32]>().prop_map(random),
    ) {
        let var = constant(x);
        let before_read = format!("{var:?}");
        prop_assert_eq!(outcome(value(&var)), Ok(x));
        prop_assert_eq!(
            before_read.as_str(),
            format!("CircuitVar::constant({})", Fr::from(x))
        );
        prop_assert_eq!(format!("{var:?}"), before_read);
        prop_assert_eq!(outcome(value(&(&var + zero()))), Ok(x));
        prop_assert_eq!(outcome(value(&(zero() + &var))), Ok(x));
        prop_assert_eq!(outcome(value(&zero())), Ok(Field::from(0u64)));
    }
}

fn refusal_at(error: ProverError) -> (&'static str, &'static str, u32) {
    let location = error.location();
    (error.name(), location.file(), location.line())
}

#[test]
fn a_constant_holds_exactly_its_field_value_and_prints_as_a_constant() {
    let decimals: Vec<&str> = VALID
        .iter()
        .flat_map(|vector| [vector.value, vector.negation])
        .collect();
    assert_eq!(
        decimals
            .iter()
            .map(|decimal| {
                let var = constant(field(decimal));
                (format!("{var:?}"), outcome(value(&var)))
            })
            .collect::<Vec<_>>(),
        decimals
            .iter()
            .map(|decimal| (
                format!("CircuitVar::constant({})", Fr::from(field(decimal))),
                Ok::<_, Refusal>(field(decimal))
            ))
            .collect::<Vec<_>>()
    );
}

#[test]
fn constant_takes_every_integer_width_and_a_bool() {
    assert_eq!(
        [
            value(&constant(u8::MAX)),
            value(&constant(u16::MAX)),
            value(&constant(u32::MAX)),
            value(&constant(u64::MAX)),
            value(&constant(u128::MAX)),
            value(&constant(true)),
            value(&constant(false)),
        ]
        .map(outcome),
        [
            "255",
            "65535",
            "4294967295",
            "18446744073709551615",
            "340282366920938463463374607431768211455",
            "1",
            "0",
        ]
        .map(|decimal| Ok(field(decimal)))
    );
}

#[test]
fn zero_is_exactly_the_constant_zero() {
    assert_eq!(
        (format!("{:?}", zero()), outcome(value(&zero()))),
        (format!("{:?}", constant(0u64)), Ok(Field::from(0u64)))
    );
}

#[test]
fn a_constant_operand_puts_its_value_on_variable_zero_and_allocates_nothing() {
    let one = Fr::one();
    assert_eq!(
        (
            exported::<EqualsSeven>(),
            check_constraints(&EqualsSeven { value: field("7") }),
            native(&EqualsSeven { value: field("8") }),
        ),
        (
            R1cs {
                header: R1csHeader::bn254(2, 0, 1, 1),
                a: vec![vec![(Fr::from(7u64), 0), (-one, 1)]],
                b: vec![vec![(one, 0)]],
                c: vec![vec![]],
                wire_labels: vec![0, 1],
            },
            Ok(1),
            Err(rule_broken(RULE, FILE)),
        )
    );
}

#[test]
fn reading_a_proof_input_fails_in_r1cs_at_the_line_of_the_read() {
    let fixture = ReadsValue { value: field("3") };
    let (_, line) = read(&constant(0u64));
    let at_the_read = (READS_VARIABLE_VALUE, FILE, line);
    assert_eq!(
        (
            fixture.check_constraints().map_err(refusal_at),
            ReadsValue::export_r1cs().map(|_| ()).map_err(refusal_at),
            fixture.export_assignment().map(|_| ()).map_err(refusal_at),
        ),
        (Err(at_the_read), Err(at_the_read), Err(at_the_read))
    );
}

#[test]
fn reading_a_proof_input_natively_returns_its_constant_value() {
    for input in ["0", "1", "3", MODULUS_MINUS_1].map(field) {
        let fixture = ReadsValue { value: input };
        let circuit = native_circuit(&fixture).expect("native proof input");
        assert_eq!(
            (outcome(read(&circuit.value).0), native(&fixture)),
            (Ok(input), Ok(())),
        );
    }
}
