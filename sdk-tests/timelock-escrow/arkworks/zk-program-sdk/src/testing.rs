use crate::{
    circuit::{labels, Circuit, ConstraintLabel, Field, LabelKind, VariableRole},
    conversion::ProofInput,
    prover::ArkworksCircuit,
    RelationError,
};

const PUBLIC_HASH_VARIABLE: usize = 1;
const PERTURBATION_SEED: u64 = 0x5eed;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tamper {
    PublicHash(Field),
    PrivateVariable { index: usize, value: Field },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FreeVariable {
    pub variable: usize,
    pub role: VariableRole,
    pub allocation: Option<ConstraintLabel>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateVariableReport {
    pub constraints: usize,
    pub private_variables: usize,
    pub free: Vec<FreeVariable>,
    pub tolerated: Vec<FreeVariable>,
}

pub fn constraint_labels<P>(proof_inputs: &P) -> Result<Vec<ConstraintLabel>, RelationError>
where
    P: ProofInput,
    P::Circuit: Circuit,
{
    Ok(ArkworksCircuit::new(proof_inputs)?
        .synthesized()?
        .matrices
        .into_labels())
}

pub fn check_tampered<P>(proof_inputs: &P, tamper: Tamper) -> Result<(), RelationError>
where
    P: ProofInput,
    P::Circuit: Circuit,
{
    let synthesized = ArkworksCircuit::new(proof_inputs)?.synthesized()?;
    let shape = synthesized.matrices.shape();
    let (variable, value) = match tamper {
        Tamper::PublicHash(value) => (PUBLIC_HASH_VARIABLE, value),
        Tamper::PrivateVariable { index, value } if index < shape.witness_variables => {
            (shape.instance_variables + index, value)
        }
        Tamper::PrivateVariable { index, .. } => return Err(RelationError::NoSuchVariable(index)),
    };
    let mut assignment = synthesized.assignment;
    let slot = assignment
        .get_mut(variable)
        .ok_or(RelationError::ProofInputsForAnotherCircuit)?;
    *slot = value;
    synthesized.matrices.check(&assignment)
}

pub fn check_private_variables<P>(proof_inputs: &P) -> Result<PrivateVariableReport, RelationError>
where
    P: ProofInput,
    P::Circuit: Circuit,
{
    let synthesized = ArkworksCircuit::new(proof_inputs)?.synthesized()?;
    let matrices = &synthesized.matrices;
    let (tolerated, free) = matrices
        .unconstrained_private_variables(&synthesized.assignment, PERTURBATION_SEED)?
        .into_iter()
        .map(|variable| {
            let allocation = labels::allocation_of(matrices.labels(), variable).cloned();
            let role = match allocation.as_ref().map(|label| label.kind) {
                Some(LabelKind::Allocation(role)) => role,
                _ => VariableRole::Constrained,
            };
            FreeVariable {
                variable,
                role,
                allocation,
            }
        })
        .partition(|free| free.role != VariableRole::Constrained);
    Ok(PrivateVariableReport {
        constraints: matrices.constraint_count(),
        private_variables: matrices.shape().witness_variables,
        free,
        tolerated,
    })
}
