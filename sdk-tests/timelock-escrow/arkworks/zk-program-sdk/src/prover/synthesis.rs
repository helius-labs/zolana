use ark_ff::{UniformRand, Zero};
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSynthesizer, OptimizationGoal, SynthesisError, SynthesisMode,
};
use ark_std::{
    cfg_iter,
    rand::{rngs::StdRng, SeedableRng},
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::ProofInputs;
use crate::{
    circuit::{
        labels, value, Circuit, CircuitLabel, CircuitSize, CircuitSystem, CircuitVar,
        ConstraintSystem, Field,
    },
    conversion::{Allocator, ProofInput},
    CircuitError, CircuitErrorKind, ProverError, ProverErrorKind,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CircuitShape {
    pub(crate) instance_variables: usize,
    pub(crate) witness_variables: usize,
}

pub(crate) struct CircuitMatrices {
    matrices: ConstraintMatrices<Field>,
    labels: Vec<CircuitLabel>,
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

    fn synthesis_shape(&self) -> CircuitSize {
        CircuitSize {
            constraints: self.matrices.num_constraints,
            public_variables: self.matrices.num_instance_variables,
            private_variables: self.matrices.num_witness_variables,
        }
    }

    fn first_differing_row(&self, other: &Self) -> Option<usize> {
        rows(&self.matrices)
            .zip(rows(&other.matrices))
            .position(|(left, right)| left != right)
    }

    pub(crate) fn matrices(&self) -> &ConstraintMatrices<Field> {
        &self.matrices
    }

    #[cfg(feature = "setup")]
    pub(crate) fn r1cs(&self) -> Result<Vec<u8>, ProverError> {
        super::snarkjs::r1cs(&self.matrices)
    }

    pub(crate) fn labels(&self) -> &[CircuitLabel] {
        &self.labels
    }

    pub(crate) fn into_labels(self) -> Vec<CircuitLabel> {
        self.labels
    }

    pub(crate) fn unconstrained_private_variables(
        &self,
        assignment: &[Field],
        seed: u64,
    ) -> Result<Vec<usize>, ProverError> {
        let instance = self.matrices.num_instance_variables;
        let private = self.matrices.num_witness_variables;
        if assignment.len() != instance + private {
            return Err(ProverErrorKind::ProofInputsForAnotherCircuit.into());
        }
        let mut rows_of = vec![Vec::new(); private];
        let mut honest = Vec::with_capacity(self.matrices.num_constraints);
        for (row, (a, b, c)) in rows(&self.matrices).enumerate() {
            for (_, variable) in a.iter().chain(b).chain(c) {
                let Some(private_index) = variable.checked_sub(instance) else {
                    continue;
                };
                let rows = rows_of
                    .get_mut(private_index)
                    .ok_or(ProverErrorKind::ProofInputsForAnotherCircuit)?;
                if rows.last() != Some(&row) {
                    rows.push(row);
                }
            }
            honest.push((
                evaluate(a, assignment)?,
                evaluate(b, assignment)?,
                evaluate(c, assignment)?,
            ));
        }
        let mut rng = StdRng::seed_from_u64(seed);
        let mut unconstrained = Vec::new();
        for (private_index, rows) in rows_of.iter().enumerate() {
            let delta = match Field::rand(&mut rng) {
                delta if delta.is_zero() => Field::from(1u64),
                delta => delta,
            };
            let variable = instance + private_index;
            let mut constrained = false;
            for row in rows {
                let (Some((a, b, c)), Some(row_a), Some(row_b), Some(row_c)) = (
                    honest.get(*row),
                    self.matrices.a.get(*row),
                    self.matrices.b.get(*row),
                    self.matrices.c.get(*row),
                ) else {
                    return Err(ProverErrorKind::ProofInputsForAnotherCircuit.into());
                };
                let shifted = |value: &Field, entries: &[(Field, usize)]| {
                    *value + delta * coefficient(entries, variable)
                };
                if shifted(a, row_a) * shifted(b, row_b) != shifted(c, row_c) {
                    constrained = true;
                    break;
                }
            }
            if !constrained {
                unconstrained.push(private_index);
            }
        }
        Ok(unconstrained)
    }

    pub(crate) fn check(&self, assignment: &[Field]) -> Result<(), ProverError> {
        let variables = self.matrices.num_instance_variables + self.matrices.num_witness_variables;
        if assignment.len() != variables {
            return Err(ProverErrorKind::ProofInputsForAnotherCircuit.into());
        }
        let check = |(row, ((a, b), c)): (usize, ((&Vec<_>, &Vec<_>), &Vec<_>))| {
            let satisfied = evaluate(a, assignment)
                .and_then(|a| Ok(a * evaluate(b, assignment)? == evaluate(c, assignment)?));
            match satisfied {
                Ok(true) => None,
                Ok(false) => Some(ProverErrorKind::ProofInputsBreakRule(Box::new(
                    labels::report(&self.labels, row),
                ))),
                Err(kind) => Some(kind),
            }
        };
        let rows = cfg_iter!(self.matrices.a)
            .zip(cfg_iter!(self.matrices.b))
            .zip(cfg_iter!(self.matrices.c))
            .enumerate();
        #[cfg(feature = "parallel")]
        let failure = rows.find_map_first(check);
        #[cfg(not(feature = "parallel"))]
        let failure = rows.map(check).find_map(|failure| failure);
        match failure {
            Some(kind) => Err(kind.into()),
            None => Ok(()),
        }
    }
}

type Row<'a> = (
    &'a [(Field, usize)],
    &'a [(Field, usize)],
    &'a [(Field, usize)],
);

fn rows(matrices: &ConstraintMatrices<Field>) -> impl Iterator<Item = Row<'_>> {
    matrices
        .a
        .iter()
        .zip(&matrices.b)
        .zip(&matrices.c)
        .map(|((a, b), c)| (a.as_slice(), b.as_slice(), c.as_slice()))
}

fn coefficient(entries: &[(Field, usize)], variable: usize) -> Field {
    entries
        .iter()
        .filter(|(_, index)| *index == variable)
        .fold(Field::zero(), |sum, (coefficient, _)| sum + coefficient)
}

fn evaluate(row: &[(Field, usize)], assignment: &[Field]) -> Result<Field, ProverErrorKind> {
    row.iter()
        .try_fold(Field::zero(), |sum, (coefficient, variable)| {
            assignment
                .get(*variable)
                .map(|value| sum + *coefficient * value)
        })
        .ok_or(ProverErrorKind::ProofInputsForAnotherCircuit)
}

fn one_public_input(instance_variables: usize) -> Result<(), ProverError> {
    if instance_variables != 2 {
        return Err(ProverErrorKind::WrongPublicInputCount.into());
    }
    Ok(())
}

fn constraint_system(mode: SynthesisMode) -> CircuitSystem {
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(mode);
    cs
}

fn circuit_matrices(cs: &CircuitSystem) -> Result<CircuitMatrices, ProverError> {
    cs.finalize();
    let matrices = cs.to_matrices().ok_or(SynthesisError::MissingCS)?;
    one_public_input(matrices.num_instance_variables)?;
    Ok(CircuitMatrices {
        matrices,
        labels: labels::take(cs),
    })
}

fn assignment_of(cs: &CircuitSystem) -> Result<Vec<Field>, CircuitError> {
    let system = cs.borrow().ok_or(SynthesisError::MissingCS)?;
    Ok([
        system.instance_assignment.as_slice(),
        system.witness_assignment.as_slice(),
    ]
    .concat())
}

pub(crate) struct Synthesized {
    pub(crate) matrices: CircuitMatrices,
    pub(crate) assignment: Vec<Field>,
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
    pub(crate) fn new(proof_inputs: &'a P) -> Result<Self, CircuitError> {
        let public_hash = value(
            proof_inputs
                .instantiate(&Allocator::native())?
                .circuit()?
                .public_hash(),
        )?;
        Ok(Self::with_public_hash(proof_inputs, public_hash))
    }

    pub(crate) fn with_public_hash(proof_inputs: &'a P, public_hash: Field) -> Self {
        Self {
            proof_inputs,
            public_hash,
        }
    }

    pub(crate) fn for_setup(placeholder: &'a P) -> Self {
        Self {
            proof_inputs: placeholder,
            public_hash: Field::zero(),
        }
    }

    pub(crate) fn check_constraints(&self, placeholder: &P) -> Result<usize, ProverError> {
        let setup = ArkworksCircuit::for_setup(placeholder).matrices()?;
        let synthesized = self.synthesized()?;
        let (setup_shape, proof_shape) = (
            setup.synthesis_shape(),
            synthesized.matrices.synthesis_shape(),
        );
        if setup_shape != proof_shape {
            return Err(ProverErrorKind::ShapeDiffers {
                setup: setup_shape,
                proof: proof_shape,
                first_apart: labels::first_apart(&setup.labels, &synthesized.matrices.labels),
            }
            .into());
        }
        if let Some(row) = setup.first_differing_row(&synthesized.matrices) {
            return Err(ProverErrorKind::ConstraintsDiffer(Box::new(labels::report(
                &synthesized.matrices.labels,
                row,
            )))
            .into());
        }
        setup.check(&synthesized.assignment)?;
        Ok(setup.constraint_count())
    }

    pub(crate) fn matrices(&self) -> Result<CircuitMatrices, ProverError> {
        let cs = constraint_system(SynthesisMode::Setup);
        self.synthesize(&cs).map_err(|error| match error.kind() {
            CircuitErrorKind::Internal(SynthesisError::AssignmentMissing) => {
                ProverError::at_origin_of(ProverErrorKind::ReadsValueDuringSetup, &error)
            }
            _ => ProverError::from(error),
        })?;
        circuit_matrices(&cs)
    }

    pub(crate) fn synthesized(&self) -> Result<Synthesized, ProverError> {
        let cs = constraint_system(SynthesisMode::Prove {
            construct_matrices: true,
        });
        self.synthesize(&cs)?;
        let assignment = assignment_of(&cs)?;
        Ok(Synthesized {
            matrices: circuit_matrices(&cs)?,
            assignment,
        })
    }

    pub(crate) fn proof_inputs(&self) -> Result<ProofInputs, CircuitError> {
        Ok(ProofInputs::from_assignment(self.assignment()?))
    }

    fn assignment(&self) -> Result<Vec<Field>, CircuitError> {
        let cs = constraint_system(SynthesisMode::Prove {
            construct_matrices: false,
        });
        self.synthesize(&cs)?;
        assignment_of(&cs)
    }

    fn synthesize(&self, cs: &CircuitSystem) -> Result<(), CircuitError> {
        let public_input = CircuitVar::input(cs, || Ok(self.public_hash))?;
        let checked = self
            .proof_inputs
            .instantiate(&Allocator::R1cs(cs.clone()))?
            .circuit()?;
        labels::check(
            cs,
            "the circuit's public hash is not the proof's public input",
            || checked.public_hash().enforce_equal(&public_input),
        )
    }
}

impl<P> ConstraintSynthesizer<Field> for ArkworksCircuit<'_, P>
where
    P: ProofInput,
    P::Circuit: Circuit,
{
    fn generate_constraints(self, cs: CircuitSystem) -> Result<(), SynthesisError> {
        self.synthesize(&cs).map_err(flatten)
    }
}

fn flatten(error: CircuitError) -> SynthesisError {
    match error.into_kind() {
        CircuitErrorKind::Internal(error) => error,
        _ => SynthesisError::Unsatisfiable,
    }
}
