use ark_bn254::Fr;
use ark_ff::One;
use zk_program_sdk::{
    circuit::{constant, value, zero, Field},
    ProverError, ZkCircuit,
};

use super::{
    fixtures::{read, EqualsSeven, ReadsValue, FILE, RULE},
    vectors::VALID,
};
use crate::harness::{
    field::field,
    fixture::{check_constraints, exported, native, outcome, rule_broken, Refusal},
    iden3::{R1cs, R1csHeader},
};

const READS_VARIABLE_VALUE: &str = "CircuitError.ReadsVariableValue";

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
#[ignore = "FINDING: value() of a proof input succeeds in the native run, where README.md says reading a variable fails in every run"]
fn reading_a_proof_input_fails_natively_as_well() {
    assert_eq!(
        native(&ReadsValue { value: field("3") }),
        Err((READS_VARIABLE_VALUE, None, FILE))
    );
}
