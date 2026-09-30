#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

use super::{snarkjs, synthesis::R1csMatrices};
use crate::ProverError;
#[cfg(not(target_arch = "wasm32"))]
use crate::ProverErrorKind;

pub struct R1cs {
    matrices: R1csMatrices,
}

impl R1cs {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProverError> {
        Ok(Self {
            matrices: snarkjs::read_r1cs(bytes)?,
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn load(path: &Path) -> Result<Self, ProverError> {
        let bytes = std::fs::read(path).map_err(|error| ProverErrorKind::R1csFile {
            path: path.to_path_buf(),
            error,
        })?;
        Self::from_bytes(&bytes)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ProverError> {
        snarkjs::r1cs(&self.matrices)
    }

    pub fn constraints(&self) -> usize {
        self.matrices.num_constraints
    }

    pub fn public_inputs(&self) -> usize {
        self.matrices.num_instance_variables.saturating_sub(1)
    }

    pub fn private_variables(&self) -> usize {
        self.matrices.num_witness_variables
    }

    pub(crate) fn matrices(&self) -> &R1csMatrices {
        &self.matrices
    }
}
