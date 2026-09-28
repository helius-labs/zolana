use ark_bn254::Fr;
use ark_ff::Field as _;
use zk_program_sdk::{
    circuit::{constant, Assert, CircuitSystem, ConstraintSystem, Constraints, Field},
    conversion::{Allocator, ProofInput},
    CircuitError, ProverError,
};

use crate::harness::fixture::{outcome, rule_broken, Refusal};

pub const RULE: &str = "the claim is the inverse of x";
pub const FILE: &str = file!();

pub const RULE_BROKEN: Refusal = rule_broken(RULE, FILE);
pub const DIVISION_BY_ZERO: Refusal = ("CircuitError.DivisionByZero", None, FILE);

pub const CLAIMED_WIRE: usize = 2;
pub const INVERSE_WIRE: usize = 3;

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Inverse {
    pub x: Field,
    pub inverse: Field,
}

impl Constraints for InverseCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.x.inverse()?.assert_equal(&self.inverse, RULE)
    }
}

pub fn honest(x: Field) -> Inverse {
    let inverse = Fr::from(x).inverse().expect("a nonzero x");
    Inverse {
        x,
        inverse: inverse.into(),
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Unasserted {
    pub x: Field,
}

impl Constraints for UnassertedCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        let _inverse = self.x.inverse()?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct InverseOfFour {
    pub inverse: Field,
}

impl Constraints for InverseOfFourCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        constant(4u64).inverse()?.assert_equal(&self.inverse, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct InverseOfZero {
    pub inverse: Field,
}

impl Constraints for InverseOfZeroCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        constant(0u64).inverse()?.assert_equal(&self.inverse, RULE)
    }
}

/// The proving synthesis alone, on a fresh constraint system: the fixture's
/// native run is skipped, so a refusal comes from the R1CS branch.
pub fn r1cs_synthesis<P: ProofInput<Circuit: Constraints>>(fixture: &P) -> Result<(), Refusal> {
    let cs: CircuitSystem = ConstraintSystem::new_ref();
    outcome(
        fixture
            .instantiate(&Allocator::R1cs(cs))
            .and_then(|circuit| circuit.constraints()),
    )
}

/// A prover error as a [`Refusal`], keeping the rule and file of a circuit
/// error that `prover_refusal` drops.
pub fn circuit_refusal(error: ProverError) -> Refusal {
    (error.name(), error.broken_rule(), error.location().file())
}
