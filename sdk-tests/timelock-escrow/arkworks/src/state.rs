use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    conversion::{Allocator, FromCircuit, ProofInput},
    Owner, RelationError,
};

use crate::circuit;

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EscrowTerms {
    pub creator: Owner,
    pub unlock: u64,
}

impl ProofInput for EscrowTerms {
    type Circuit = circuit::EscrowTerms;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::EscrowTerms, RelationError> {
        Ok(circuit::EscrowTerms {
            creator: self.creator.instantiate(allocator)?,
            unlock: self.unlock.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for EscrowTerms {
    fn from_circuit(circuit: &circuit::EscrowTerms) -> Result<Self, RelationError> {
        Ok(Self {
            creator: Owner::from_circuit(&circuit.creator)?,
            unlock: u64::from_circuit(&circuit.unlock)?,
        })
    }
}
