use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, OptimizationGoal, SynthesisError};

#[cfg(any(feature = "client", feature = "setup"))]
mod groth16;

#[cfg(feature = "setup")]
pub use groth16::VerifyingKeyExport;
#[cfg(feature = "client")]
pub use groth16::{CompressedProof, SolanaProof};
#[cfg(any(feature = "client", feature = "setup"))]
pub use groth16::{Groth16Keys, Proof, ProvingKey, SolanaVerifyingKey, VerifyingKey};

use crate::{
    circuit::{value, Circuit, CircuitSystem, CircuitVar, ConstraintSystem, Field},
    conversion::{field_bytes, Allocator, ProofInput},
    RelationError,
};

#[derive(Clone, Debug)]
pub struct ArkworksCircuit<P> {
    proof_inputs: P,
    public_hash: Field,
}

impl<P> ArkworksCircuit<P>
where
    P: ProofInput + Clone,
    P::Circuit: Circuit,
{
    pub fn new(proof_inputs: P) -> Result<Self, RelationError> {
        let public_hash = value(
            proof_inputs
                .instantiate(&Allocator::native())?
                .circuit()?
                .public_hash(),
        )?;
        Ok(Self {
            proof_inputs,
            public_hash,
        })
    }

    pub fn with_public_hash(proof_inputs: P, public_hash: Field) -> Self {
        Self {
            proof_inputs,
            public_hash,
        }
    }

    pub fn public_hash(&self) -> Field {
        self.public_hash
    }

    pub fn public_hash_bytes(&self) -> [u8; 32] {
        field_bytes(&self.public_hash)
    }

    pub fn check_constraints(&self) -> Result<usize, RelationError> {
        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        self.clone().generate_constraints(cs.clone())?;
        if cs.num_instance_variables() != 2 {
            return Err(RelationError::Violated(
                "a circuit has exactly one public input, its public hash",
            ));
        }
        match cs.which_is_unsatisfied()? {
            Some(constraint) => Err(RelationError::Unsatisfied(constraint)),
            None => Ok(cs.num_constraints()),
        }
    }
}

impl<P> ConstraintSynthesizer<Field> for ArkworksCircuit<P>
where
    P: ProofInput,
    P::Circuit: Circuit,
{
    fn generate_constraints(self, cs: CircuitSystem) -> Result<(), SynthesisError> {
        let public_hash = CircuitVar::new_input(cs.clone(), || Ok(self.public_hash))?;
        self.proof_inputs
            .instantiate(&Allocator::R1cs(cs))?
            .circuit()?
            .public_hash()
            .enforce_equal(&public_hash)
    }
}
