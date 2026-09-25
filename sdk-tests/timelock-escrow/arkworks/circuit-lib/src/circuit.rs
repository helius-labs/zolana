use ark_r1cs_std::eq::EqGadget;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisError,
};

use crate::{
    convert::field_bytes, value, Allocator, Assert, CircuitSystem, CircuitVar, Field, ProofInput,
    RelationError,
};

pub trait Circuit {
    fn circuit(&self) -> Result<CircuitVar, RelationError>;

    fn public_hash(&self) -> &CircuitVar;
}

#[derive(Clone, Debug)]
pub struct PublicHash(CircuitVar);

impl PublicHash {
    pub fn new(value: CircuitVar) -> Self {
        Self(value)
    }
}

impl ProofInput for PublicHash {
    type Circuit = CircuitVar;

    fn instantiate(&self, allocator: &Allocator) -> Result<CircuitVar, RelationError> {
        allocator.public_input(&self.0)
    }
}

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
        let circuit = proof_inputs.instantiate(&Allocator::Native)?;
        circuit
            .circuit()?
            .assert_equal(circuit.public_hash(), "the public hash does not match")?;
        let public_hash = value(circuit.public_hash())?;
        Ok(Self {
            proof_inputs,
            public_hash,
        })
    }

    pub fn unchecked(proof_inputs: P) -> Result<Self, RelationError> {
        let public_hash = value(proof_inputs.instantiate(&Allocator::Native)?.public_hash())?;
        Ok(Self {
            proof_inputs,
            public_hash,
        })
    }

    pub fn public_hash(&self) -> Field {
        self.public_hash
    }

    pub fn public_hash_bytes(&self) -> [u8; 32] {
        field_bytes(&self.public_hash)
    }

    pub fn check_constraints(&self) -> Result<usize, RelationError> {
        let cs = ConstraintSystem::<Field>::new_ref();
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
        let circuit = self.proof_inputs.instantiate(&Allocator::R1cs(cs))?;
        circuit.circuit()?.enforce_equal(circuit.public_hash())
    }
}
