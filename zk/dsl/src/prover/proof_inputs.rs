use ark_bn254::Fr;
use ark_ff::One;

use super::snarkjs;
use crate::{conversion::be_bytes, ProverError, ProverErrorKind};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofInputs {
    values: Vec<Fr>,
    public_inputs: Option<usize>,
}

impl ProofInputs {
    pub(crate) fn new(values: Vec<Fr>) -> Result<Self, ProverError> {
        if values.first() != Some(&Fr::one()) {
            return Err(ProverErrorKind::InvalidProofInputs(
                "the first value is not the constant one",
            )
            .into());
        }
        Ok(Self {
            values,
            public_inputs: None,
        })
    }

    pub(crate) fn from_assignment(values: Vec<Fr>, public_inputs: usize) -> Self {
        Self {
            values,
            public_inputs: Some(public_inputs),
        }
    }

    /// Reads a WTNS assignment. WTNS does not record the public-input count;
    /// obtain its public inputs from a prover's verified `ProofResult` instead.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProverError> {
        Self::new(snarkjs::read_wtns(bytes)?)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ProverError> {
        snarkjs::wtns(&self.values)
    }

    /// Returns the public inputs in proof order, only when synthesis
    /// established their count. Raw WTNS assignments reject it.
    pub fn public_inputs(&self) -> Result<Vec<[u8; 32]>, ProverError> {
        let count = self
            .public_inputs
            .ok_or(ProverErrorKind::InvalidProofInputs(
                "the assignment has no established public input count",
            ))?;
        public_inputs(&self.values, count)
    }

    pub(crate) fn values(&self) -> &[Fr] {
        &self.values
    }
}

/// The `count` public inputs of an assignment: the values after the constant
/// one, as 32-byte big-endian field elements.
pub(crate) fn public_inputs(values: &[Fr], count: usize) -> Result<Vec<[u8; 32]>, ProverError> {
    Ok(values
        .get(1..=count)
        .ok_or(ProverErrorKind::InvalidProofInputs(
            "the values hold fewer public inputs than the circuit",
        ))?
        .iter()
        .map(be_bytes)
        .collect())
}
