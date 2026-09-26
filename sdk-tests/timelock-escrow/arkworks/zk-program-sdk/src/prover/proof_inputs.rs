use ark_ff::One;

use super::snarkjs;
use crate::{circuit::Field, conversion::field_bytes, RelationError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofInputs {
    values: Vec<Field>,
}

impl ProofInputs {
    pub(crate) fn new(values: Vec<Field>) -> Result<Self, RelationError> {
        if values.first() != Some(&Field::one()) {
            return Err(RelationError::InvalidProofInputs(
                "the first value is not the constant one",
            ));
        }
        if values.get(1).is_none() {
            return Err(RelationError::InvalidProofInputs(
                "the values hold no public hash",
            ));
        }
        Ok(Self { values })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RelationError> {
        Self::new(snarkjs::read_wtns(bytes)?)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, RelationError> {
        snarkjs::wtns(&self.values)
    }

    pub fn public_hash(&self) -> Result<[u8; 32], RelationError> {
        self.values
            .get(1)
            .map(field_bytes)
            .ok_or(RelationError::InvalidProofInputs(
                "the values hold no public hash",
            ))
    }

    pub(crate) fn values(&self) -> &[Field] {
        &self.values
    }
}
