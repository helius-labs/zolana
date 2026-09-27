use ark_bn254::Fr;
use ark_ff::One;

use super::snarkjs;
use crate::{conversion::be_bytes, ProverError, ProverErrorKind};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofInputs {
    values: Vec<Fr>,
}

impl ProofInputs {
    pub(crate) fn new(values: Vec<Fr>) -> Result<Self, ProverError> {
        if values.first() != Some(&Fr::one()) {
            return Err(ProverErrorKind::InvalidProofInputs(
                "the first value is not the constant one",
            )
            .into());
        }
        if values.get(1).is_none() {
            return Err(
                ProverErrorKind::InvalidProofInputs("the values hold no public hash").into(),
            );
        }
        Ok(Self { values })
    }

    pub(crate) fn from_assignment(values: Vec<Fr>) -> Self {
        Self { values }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProverError> {
        Self::new(snarkjs::read_wtns(bytes)?)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ProverError> {
        snarkjs::wtns(&self.values)
    }

    pub fn public_hash(&self) -> Result<[u8; 32], ProverError> {
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
