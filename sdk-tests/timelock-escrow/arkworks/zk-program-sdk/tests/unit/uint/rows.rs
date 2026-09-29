//! Hand derivations of the rows a `Uint` gadget exports, and of the witnesses
//! that satisfy them. A range check of a linear form v over n bits is n
//! boolean rows `(1 - b_i) * b_i = 0`, one per bit wire in allocation order,
//! then the linear row `sum(2^i * b_i) - v = 0`.

use std::collections::BTreeMap;

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field as _, One, PrimeField, Zero};
use num_bigint::BigUint;
use zk_program_sdk::{
    circuit::{Constraints, Field},
    conversion::Allocator,
    CircuitError, ZkCircuit,
};

use crate::harness::iden3::{R1cs, Row};

pub type Terms = [(Fr, usize)];
pub type Constraint = (Row, Row, Row);
pub type Rows = (Vec<Row>, Vec<Row>, Vec<Row>);
pub type Refused = (&'static str, String, &'static str);

pub fn refused<T>(result: Result<T, CircuitError>) -> Result<T, Refused> {
    result.map_err(|error| (error.name(), error.to_string(), error.location().file()))
}

/// The native run of a fixture, refused with its error's name, message and
/// file, so a `ValueTooLarge` names its width.
pub fn native<F: ZkCircuit>(fixture: &F) -> Result<(), Refused> {
    refused(
        fixture
            .instantiate(&Allocator::native())
            .and_then(|circuit| circuit.constraints()),
    )
}

pub fn too_large(bits: usize, file: &'static str) -> Refused {
    (
        "CircuitError.ValueTooLarge",
        format!("a value does not fit in {bits} bits"),
        file,
    )
}

pub fn broken(rule: &'static str, file: &'static str) -> Refused {
    ("CircuitError.RuleBroken", rule.to_string(), file)
}

pub fn int(value: u128) -> Fr {
    Fr::from(value)
}

pub fn power_of_two(bits: u32) -> Fr {
    Fr::from(2u64).pow([u64::from(bits)])
}

pub fn max(bits: u32) -> Fr {
    power_of_two(bits) - Fr::one()
}

pub fn field(value: Fr) -> Field {
    Field::from(value)
}

pub fn integer(value: Fr) -> BigUint {
    BigUint::from(value.into_bigint())
}

pub fn lc(terms: &Terms) -> Row {
    let mut combined = BTreeMap::new();
    for (coefficient, wire) in terms {
        *combined.entry(*wire).or_insert(Fr::ZERO) += coefficient;
    }
    combined
        .into_iter()
        .filter(|(_, coefficient)| !coefficient.is_zero())
        .map(|(wire, coefficient)| (coefficient, wire))
        .collect()
}

pub fn one() -> Row {
    vec![(Fr::one(), 0)]
}

pub fn boolean(wire: usize) -> Constraint {
    (
        lc(&[(Fr::one(), 0), (-Fr::one(), wire)]),
        vec![(Fr::one(), wire)],
        vec![],
    )
}

pub fn linear(terms: &Terms) -> Constraint {
    (lc(terms), one(), vec![])
}

pub fn product(a: &Terms, b: &Terms, c: &Terms) -> Constraint {
    (lc(a), lc(b), lc(c))
}

pub fn decomposition(value: &Terms, first_bit: usize, bits: usize) -> Vec<Constraint> {
    let bit_wires = first_bit..first_bit + bits;
    let mut sum: Vec<(Fr, usize)> = bit_wires
        .clone()
        .zip(0u32..)
        .map(|(wire, index)| (power_of_two(index), wire))
        .collect();
    sum.extend(
        value
            .iter()
            .map(|(coefficient, wire)| (-*coefficient, *wire)),
    );
    bit_wires.map(boolean).chain([linear(&sum)]).collect()
}

pub fn golden(parts: impl IntoIterator<Item = Vec<Constraint>>) -> Rows {
    let mut rows: Rows = (vec![], vec![], vec![]);
    for (a, b, c) in parts.into_iter().flatten() {
        rows.0.push(a);
        rows.1.push(b);
        rows.2.push(c);
    }
    rows
}

pub fn rows(r1cs: R1cs) -> Rows {
    (r1cs.a, r1cs.b, r1cs.c)
}

pub fn low_bits(value: Fr, bits: usize) -> Vec<Fr> {
    let value = value.into_bigint();
    (0..bits)
        .map(|index| Fr::from(u64::from(value.get_bit(index))))
        .collect()
}

pub fn bit_pattern(pattern: u64, bits: usize) -> Vec<Fr> {
    (0..bits)
        .map(|index| Fr::from((pattern >> index) & 1))
        .collect()
}

/// `witness` with the wires from `first_bit` set to `bits`.
pub fn with_bits(mut witness: Vec<Fr>, first_bit: usize, bits: &[Fr]) -> Vec<Fr> {
    witness
        .get_mut(first_bit..first_bit + bits.len())
        .expect("bit wires")
        .copy_from_slice(bits);
    witness
}

/// `witness` with the wires from `first_bit` set to the low `bits` bits of
/// `value`, the decomposition arkworks assigns even when `value` does not fit.
pub fn with_low_bits(witness: Vec<Fr>, first_bit: usize, bits: usize, value: Fr) -> Vec<Fr> {
    with_bits(witness, first_bit, &low_bits(value, bits))
}
