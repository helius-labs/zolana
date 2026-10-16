use zolana_program::{
    circuit::{Assert, Circuit, Field},
    conversion::ProofInput,
    CircuitError,
};

use crate::harness::fixture::{rule_broken, Refusal};

pub const RULE: &str = "the power is x to the exponent";
pub const FILE: &str = file!();

pub const RULE_BROKEN: Refusal = rule_broken(RULE, FILE);

pub const POWER_WIRE: usize = 2;
pub const FIRST_WITNESS_WIRE: usize = 3;

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Pow<const EXPONENT: u64> {
    pub x: Field,
    pub power: Field,
}

impl<const EXPONENT: u64> Circuit for PowCircuit<EXPONENT> {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        self.x.pow(EXPONENT)?.assert_equal(&self.power, RULE)
    }
}

pub type Pow5 = Pow<5>;

/// The witnesses `pow` allocates for `exponent`: a square for every bit
/// after the leading one and a product for every set bit after it.
pub const fn witnesses(exponent: u64) -> usize {
    match exponent {
        0 => 0,
        exponent => (u64::BITS - exponent.leading_zeros() - 1 + exponent.count_ones() - 1) as usize,
    }
}
