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
    /// obtain its public hash from a prover's verified `ProofResult` instead.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProverError> {
        Self::new(snarkjs::read_wtns(bytes)?)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ProverError> {
        snarkjs::wtns(&self.values)
    }

    /// Returns the hash only when synthesis established exactly one public
    /// input. Raw WTNS assignments and circuits without public inputs reject it.
    pub fn public_hash(&self) -> Result<[u8; 32], ProverError> {
        if self.public_inputs != Some(1) {
            return Err(ProverErrorKind::InvalidProofInputs(
                "the assignment has no established single public hash",
            )
            .into());
        }
        Ok(self
            .values
            .get(1)
            .map(be_bytes)
            .ok_or(ProverErrorKind::InvalidProofInputs(
                "the values hold no public hash",
            ))?)
    }

    pub(crate) fn values(&self) -> &[Fr] {
        &self.values
    }
}
