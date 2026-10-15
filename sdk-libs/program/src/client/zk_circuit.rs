use crate::{
    circuit::Circuit,
    conversion::{Placeholder, ProofInput},
    prover::{ArkworksCircuit, ProofInputs},
    ProverError,
};

/// Shared checking and export operations for any supported circuit output.
pub trait ZkCircuit: ProofInput<Circuit: Circuit> + Placeholder {
    fn check_constraints(&self) -> Result<usize, ProverError> {
        ArkworksCircuit::new(self)?.check_constraints(&Self::placeholder()?)
    }

    #[cfg(feature = "setup")]
    fn export_r1cs() -> Result<Vec<u8>, ProverError> {
        let placeholder = Self::placeholder()?;
        ArkworksCircuit::for_setup(&placeholder).matrices()?.r1cs()
    }

    #[cfg(feature = "setup")]
    fn export_picus_r1cs() -> Result<Vec<u8>, ProverError> {
        let placeholder = Self::placeholder()?;
        ArkworksCircuit::for_setup(&placeholder)
            .matrices()?
            .picus_r1cs()
    }

    fn proof_inputs(&self) -> Result<ProofInputs, ProverError> {
        Ok(ArkworksCircuit::new(self)?.proof_inputs()?)
    }

    fn export_assignment(&self) -> Result<Vec<u8>, ProverError> {
        self.proof_inputs()?.to_bytes()
    }
}

impl<T: ProofInput<Circuit: Circuit> + Placeholder> ZkCircuit for T {}
