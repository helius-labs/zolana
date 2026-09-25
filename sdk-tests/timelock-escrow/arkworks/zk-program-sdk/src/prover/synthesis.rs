use ark_ff::Zero;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, OptimizationGoal, SynthesisError, SynthesisMode};

use crate::{
    circuit::{value, Circuit, CircuitSystem, CircuitVar, ConstraintSystem, Field},
    conversion::{field_bytes, Allocator, ProofInput},
    RelationError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CircuitShape {
    pub(crate) instance_variables: usize,
    pub(crate) witness_variables: usize,
}

pub(crate) struct ArkworksCircuit<'a, P> {
    proof_inputs: &'a P,
    public_hash: Field,
}

impl<P> Clone for ArkworksCircuit<'_, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P> Copy for ArkworksCircuit<'_, P> {}

impl<'a, P> ArkworksCircuit<'a, P>
where
    P: ProofInput,
    P::Circuit: Circuit,
{
    pub(crate) fn new(proof_inputs: &'a P) -> Result<Self, RelationError> {
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

    pub(crate) fn for_setup(placeholder: &'a P) -> Self {
        Self {
            proof_inputs: placeholder,
            public_hash: Field::zero(),
        }
    }

    pub(crate) fn public_hash_bytes(&self) -> [u8; 32] {
        field_bytes(&self.public_hash)
    }

    pub(crate) fn check_constraints(&self) -> Result<usize, RelationError> {
        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        self.generate_constraints(cs.clone())?;
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

    pub(crate) fn shape(&self) -> Result<CircuitShape, RelationError> {
        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);
        self.generate_constraints(cs.clone())?;
        cs.finalize();
        Ok(CircuitShape {
            instance_variables: cs.num_instance_variables(),
            witness_variables: cs.num_witness_variables(),
        })
    }
}

impl<P> ConstraintSynthesizer<Field> for ArkworksCircuit<'_, P>
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
