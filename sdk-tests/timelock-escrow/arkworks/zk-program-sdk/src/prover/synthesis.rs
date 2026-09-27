use ark_bn254::Fr;
use ark_ff::{UniformRand, Zero};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, Matrix, OptimizationGoal, SynthesisError, SynthesisMode,
    R1CS_PREDICATE_LABEL,
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
        ConstraintSystem, Constraints,
    },
    conversion::{Allocator, ProofInput},
    CircuitError, CircuitErrorKind, ProverError, ProverErrorKind,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CircuitShape {
    pub(crate) instance_variables: usize,
    pub(crate) witness_variables: usize,
}

/// The a, b and c matrices of the R1CS predicate plus the system counts that
/// arkworks 0.5's `ConstraintMatrices` used to carry.
pub(crate) struct R1csMatrices {
    matrices: [Matrix<Fr>; 3],
    pub(crate) num_instance_variables: usize,
    pub(crate) num_witness_variables: usize,
    pub(crate) num_constraints: usize,
}

impl R1csMatrices {
    pub(crate) fn a(&self) -> &Matrix<Fr> {
        &self.matrices[0]
    }

    pub(crate) fn b(&self) -> &Matrix<Fr> {
        &self.matrices[1]
    }

    pub(crate) fn c(&self) -> &Matrix<Fr> {
        &self.matrices[2]
    }

    /// The matrices in a, b, c order, as `R1CSToQAP` implementations take them.
    pub(crate) fn as_slice(&self) -> &[Matrix<Fr>] {
        &self.matrices
    }
}

pub(crate) struct CircuitMatrices {
    matrices: R1csMatrices,
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

    pub(crate) fn matrices(&self) -> &R1csMatrices {
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
        assignment: &[Fr],
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
            let delta = match Fr::rand(&mut rng) {
                delta if delta.is_zero() => Fr::from(1u64),
                delta => delta,
            };
            let variable = instance + private_index;
            let mut constrained = false;
            for row in rows {
                let (Some((a, b, c)), Some(row_a), Some(row_b), Some(row_c)) = (
                    honest.get(*row),
                    self.matrices.a().get(*row),
                    self.matrices.b().get(*row),
                    self.matrices.c().get(*row),
                ) else {
                    return Err(ProverErrorKind::ProofInputsForAnotherCircuit.into());
                };
                let shifted = |value: &Fr, entries: &[(Fr, usize)]| {
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

    pub(crate) fn check(&self, assignment: &[Fr]) -> Result<(), ProverError> {
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
        let rows = cfg_iter!(self.matrices.a())
            .zip(cfg_iter!(self.matrices.b()))
            .zip(cfg_iter!(self.matrices.c()))
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

type Row<'a> = (&'a [(Fr, usize)], &'a [(Fr, usize)], &'a [(Fr, usize)]);

fn rows(matrices: &R1csMatrices) -> impl Iterator<Item = Row<'_>> {
    matrices
        .a()
        .iter()
        .zip(matrices.b())
        .zip(matrices.c())
        .map(|((a, b), c)| (a.as_slice(), b.as_slice(), c.as_slice()))
}

fn coefficient(entries: &[(Fr, usize)], variable: usize) -> Fr {
    entries
        .iter()
        .filter(|(_, index)| *index == variable)
        .fold(Fr::zero(), |sum, (coefficient, _)| sum + coefficient)
}

fn evaluate(row: &[(Fr, usize)], assignment: &[Fr]) -> Result<Fr, ProverErrorKind> {
    row.iter()
        .try_fold(Fr::zero(), |sum, (coefficient, variable)| {
            assignment
                .get(*variable)
                .map(|value| sum + *coefficient * value)
        })
        .ok_or(ProverErrorKind::ProofInputsForAnotherCircuit)
}

fn check_public_inputs(instance_variables: usize, public_inputs: usize) -> Result<(), ProverError> {
    if instance_variables != public_inputs + 1 {
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

fn circuit_matrices(
    cs: &CircuitSystem,
    public_inputs: usize,
) -> Result<CircuitMatrices, ProverError> {
    cs.finalize();
    // The circuits synthesize R1CS constraints only, so the R1CS predicate is
    // the only entry in the map and holds exactly the a, b and c matrices.
    let mut predicates = cs.to_matrices()?;
    let r1cs = predicates
        .remove(R1CS_PREDICATE_LABEL)
        .filter(|_| predicates.is_empty())
        .ok_or(ProverErrorKind::Internal(SynthesisError::PredicateNotFound))?;
    let matrices: [Matrix<Fr>; 3] = r1cs
        .try_into()
        .map_err(|_| ProverErrorKind::Internal(SynthesisError::ArityMismatch))?;
    let matrices = R1csMatrices {
        matrices,
        num_instance_variables: cs.num_instance_variables(),
        num_witness_variables: cs.num_witness_variables(),
        num_constraints: cs.num_constraints(),
    };
    check_public_inputs(matrices.num_instance_variables, public_inputs)?;
    Ok(CircuitMatrices {
        matrices,
        labels: labels::take(cs),
    })
}

fn assignment_of(cs: &CircuitSystem) -> Result<Vec<Fr>, CircuitError> {
    let system = cs.borrow().ok_or(SynthesisError::MissingCS)?;
    Ok([system.instance_assignment()?, system.witness_assignment()?].concat())
}

pub(crate) struct Synthesized {
    pub(crate) matrices: CircuitMatrices,
    pub(crate) assignment: Vec<Fr>,
}

#[derive(Clone, Copy)]
pub struct PublicHash(Fr);

#[derive(Clone, Copy)]
pub struct NoPublicInputs;

/// Public only so that `testing` can bound on it; the private module keeps it
/// unnameable outside the crate.
pub trait Statement<S>: Sized {
    const PUBLIC_INPUTS: usize;

    fn setup() -> S;

    fn native<P: ProofInput<Circuit = Self>>(proof_inputs: &P) -> Result<S, CircuitError>;

    fn constrain(
        cs: &CircuitSystem,
        statement: &S,
        instantiate: impl FnOnce() -> Result<Self, CircuitError>,
    ) -> Result<(), CircuitError>;
}

impl<C: Circuit> Statement<PublicHash> for C {
    const PUBLIC_INPUTS: usize = 1;

    fn setup() -> PublicHash {
        PublicHash(Fr::zero())
    }

    fn native<P: ProofInput<Circuit = Self>>(proof_inputs: &P) -> Result<PublicHash, CircuitError> {
        let public_hash = value(
            proof_inputs
                .instantiate(&Allocator::native())?
                .circuit()?
                .public_hash(),
        )?;
        Ok(PublicHash(public_hash.into()))
    }

    fn constrain(
        cs: &CircuitSystem,
        statement: &PublicHash,
        instantiate: impl FnOnce() -> Result<Self, CircuitError>,
    ) -> Result<(), CircuitError> {
        let public_input = CircuitVar::input(cs, || Ok(statement.0))?;
        let checked = instantiate()?.circuit()?;
        labels::check(
            cs,
            "the circuit's public hash is not the proof's public input",
            || checked.public_hash().enforce_equal(&public_input),
        )
    }
}

impl<C: Constraints> Statement<NoPublicInputs> for C {
    const PUBLIC_INPUTS: usize = 0;

    fn setup() -> NoPublicInputs {
        NoPublicInputs
    }

    fn native<P: ProofInput<Circuit = Self>>(
        proof_inputs: &P,
    ) -> Result<NoPublicInputs, CircuitError> {
        proof_inputs
            .instantiate(&Allocator::native())?
            .constraints()?;
        Ok(NoPublicInputs)
    }

    fn constrain(
        _cs: &CircuitSystem,
        _statement: &NoPublicInputs,
        instantiate: impl FnOnce() -> Result<Self, CircuitError>,
    ) -> Result<(), CircuitError> {
        instantiate()?.constraints()
    }
}

pub(crate) struct ArkworksCircuit<'a, P, S> {
    proof_inputs: &'a P,
    statement: S,
}

impl<P, S: Copy> Clone for ArkworksCircuit<'_, P, S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P, S: Copy> Copy for ArkworksCircuit<'_, P, S> {}

impl<'a, P> ArkworksCircuit<'a, P, PublicHash> {
    pub(crate) fn with_public_hash(proof_inputs: &'a P, public_hash: Fr) -> Self {
        Self {
            proof_inputs,
            statement: PublicHash(public_hash),
        }
    }
}

impl<'a, P, S> ArkworksCircuit<'a, P, S>
where
    P: ProofInput,
    P::Circuit: Statement<S>,
{
    pub(crate) fn new(proof_inputs: &'a P) -> Result<Self, CircuitError> {
        Ok(Self {
            proof_inputs,
            statement: <P::Circuit as Statement<S>>::native(proof_inputs)?,
        })
    }

    pub(crate) fn for_setup(placeholder: &'a P) -> Self {
        Self {
            proof_inputs: placeholder,
            statement: <P::Circuit as Statement<S>>::setup(),
        }
    }

    pub(crate) fn check_constraints(&self, placeholder: &P) -> Result<usize, ProverError> {
        let setup = ArkworksCircuit::<P, S>::for_setup(placeholder).matrices()?;
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
        circuit_matrices(&cs, <P::Circuit as Statement<S>>::PUBLIC_INPUTS)
    }

    pub(crate) fn synthesized(&self) -> Result<Synthesized, ProverError> {
        let cs = constraint_system(SynthesisMode::Prove {
            construct_matrices: true,
            generate_lc_assignments: true,
        });
        self.synthesize(&cs)?;
        let assignment = assignment_of(&cs)?;
        Ok(Synthesized {
            matrices: circuit_matrices(&cs, <P::Circuit as Statement<S>>::PUBLIC_INPUTS)?,
            assignment,
        })
    }

    pub(crate) fn proof_inputs(&self) -> Result<ProofInputs, CircuitError> {
        Ok(ProofInputs::from_assignment(self.assignment()?))
    }

    fn assignment(&self) -> Result<Vec<Fr>, CircuitError> {
        let cs = constraint_system(SynthesisMode::Prove {
            construct_matrices: false,
            generate_lc_assignments: true,
        });
        self.synthesize(&cs)?;
        assignment_of(&cs)
    }

    fn synthesize(&self, cs: &CircuitSystem) -> Result<(), CircuitError> {
        <P::Circuit as Statement<S>>::constrain(cs, &self.statement, || {
            self.proof_inputs.instantiate(&Allocator::R1cs(cs.clone()))
        })
    }
}

impl<P, S> ConstraintSynthesizer<Fr> for ArkworksCircuit<'_, P, S>
where
    P: ProofInput,
    P::Circuit: Statement<S>,
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
