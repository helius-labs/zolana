use ark_ff::Zero;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget};
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSynthesizer, OptimizationGoal, SynthesisError, SynthesisMode,
};

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

pub(crate) struct CircuitMatrices {
    matrices: ConstraintMatrices<Field>,
}

impl CircuitMatrices {
    pub(crate) fn shape(&self) -> CircuitShape {
        CircuitShape {
            instance_variables: self.matrices.num_instance_variables,
            witness_variables: self.matrices.num_witness_variables,
        }
    }

    pub(crate) fn constraint_count(&self) -> usize {
        self.matrices.num_constraints
    }

    pub(crate) fn matrices(&self) -> &ConstraintMatrices<Field> {
        &self.matrices
    }

    pub(crate) fn check(&self, assignment: &[Field]) -> Result<(), RelationError> {
        let variables = self.matrices.num_instance_variables + self.matrices.num_witness_variables;
        if assignment.len() != variables {
            return Err(RelationError::ProofInputsForAnotherCircuit);
        }
        let rows = self
            .matrices
            .a
            .iter()
            .zip(&self.matrices.b)
            .zip(&self.matrices.c);
        for (constraint, ((a, b), c)) in rows.enumerate() {
            if evaluate(a, assignment)? * evaluate(b, assignment)? != evaluate(c, assignment)? {
                return Err(RelationError::Unsatisfied(constraint.to_string()));
            }
        }
        Ok(())
    }
}

fn evaluate(row: &[(Field, usize)], assignment: &[Field]) -> Result<Field, RelationError> {
    row.iter()
        .try_fold(Field::zero(), |sum, (coefficient, variable)| {
            assignment
                .get(*variable)
                .map(|value| sum + *coefficient * value)
        })
        .ok_or(RelationError::ProofInputsForAnotherCircuit)
}

fn one_public_input(instance_variables: usize) -> Result<(), RelationError> {
    if instance_variables != 2 {
        return Err(RelationError::Violated(
            "a circuit has exactly one public input, its public hash",
        ));
    }
    Ok(())
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
        one_public_input(cs.num_instance_variables())?;
        match cs.which_is_unsatisfied()? {
            Some(constraint) => Err(RelationError::Unsatisfied(constraint)),
            None => Ok(cs.num_constraints()),
        }
    }

    pub(crate) fn matrices(&self) -> Result<CircuitMatrices, RelationError> {
        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);
        self.generate_constraints(cs.clone())?;
        cs.finalize();
        let matrices = cs.to_matrices().ok_or(SynthesisError::MissingCS)?;
        one_public_input(matrices.num_instance_variables)?;
        Ok(CircuitMatrices { matrices })
    }

    pub(crate) fn assignment(&self) -> Result<Vec<Field>, RelationError> {
        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: false,
        });
        self.generate_constraints(cs.clone())?;
        let system = cs.borrow().ok_or(SynthesisError::MissingCS)?;
        Ok([
            system.instance_assignment.as_slice(),
            system.witness_assignment.as_slice(),
        ]
        .concat())
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
