use ark_bn254::Fr;
use ark_ff::Field as _;
use zk_program_sdk::{
    circuit::{constant, Assert, Constraints, Field},
    conversion::ProofInput,
    CircuitError,
};

use crate::harness::fixture::{rule_broken, Refusal};

pub const RULE: &str = "the quotient is the dividend over the divisor";
pub const FILE: &str = file!();

pub const RULE_BROKEN: Refusal = rule_broken(RULE, FILE);
pub const DIVISION_BY_ZERO: Refusal = ("CircuitError.DivisionByZero", None, FILE);

pub const QUOTIENT_WIRE: usize = 3;
pub const INVERSE_WIRE: usize = 4;
pub const PRODUCT_WIRE: usize = 5;

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Div {
    pub dividend: Field,
    pub divisor: Field,
    pub quotient: Field,
}

impl Constraints for DivCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.dividend
            .div(&self.divisor)?
            .assert_equal(&self.quotient, RULE)
    }
}

pub fn inverse_of(divisor: Field) -> Field {
    Fr::from(divisor)
        .inverse()
        .expect("a nonzero divisor")
        .into()
}

pub fn honest(dividend: Field, divisor: Field) -> Div {
    Div {
        dividend,
        divisor,
        quotient: dividend * inverse_of(divisor),
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ByFour {
    pub dividend: Field,
    pub quotient: Field,
}

impl Constraints for ByFourCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.dividend
            .div(&constant(4u64))?
            .assert_equal(&self.quotient, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct FourOver {
    pub divisor: Field,
    pub quotient: Field,
}

impl Constraints for FourOverCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        constant(4u64)
            .div(&self.divisor)?
            .assert_equal(&self.quotient, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ByZero {
    pub dividend: Field,
    pub quotient: Field,
}

impl Constraints for ByZeroCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.dividend
            .div(&constant(0u64))?
            .assert_equal(&self.quotient, RULE)
    }
}
