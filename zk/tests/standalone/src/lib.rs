//! A circuit that depends only on the zk DSL and gadgets. The derives generate
//! paths under `::zolana_program`, so the crate root names the DSL that way.

extern crate zolana_zk_dsl as zolana_program;

use zolana_zk_dsl::{
    circuit::{Assert, Circuit, CircuitType, CircuitVar, Field, PublicHashOutput},
    conversion::ProofInput,
    CircuitError,
};
use zolana_zk_gadgets::poseidon;

pub const RULE: &str = "the commitment hashes the point";

#[derive(Clone, Copy, Debug, PartialEq, Eq, CircuitType)]
pub struct Point {
    pub x: Field,
    pub y: Field,
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Opening {
    pub point: Point,
    pub commitment: Field,
}

impl Circuit for OpeningCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        poseidon(&[self.point.x.clone(), self.point.y.clone()])?
            .assert_equal(&self.commitment, RULE)
    }
}

/// The commitment to a point, bound as the proof's one public input.
pub struct Commitment(CircuitVar);

impl PublicHashOutput for Commitment {
    fn public_hash(&self) -> &CircuitVar {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct PublicOpening {
    pub point: Point,
}

impl Circuit for PublicOpeningCircuit {
    type Output = Commitment;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        Ok(Commitment(poseidon(&[
            self.point.x.clone(),
            self.point.y.clone(),
        ])?))
    }
}
