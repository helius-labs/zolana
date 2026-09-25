use circuit_lib::{poseidon, zero, Allocator, CircuitVar, DataHash, ProofInput, RelationError};

#[derive(Clone, Debug)]
pub struct EscrowTerms {
    pub creator: CircuitVar,
    pub unlock: CircuitVar,
}

impl Default for EscrowTerms {
    fn default() -> Self {
        Self {
            creator: zero(),
            unlock: zero(),
        }
    }
}

impl DataHash for EscrowTerms {
    fn hash(&self) -> Result<CircuitVar, RelationError> {
        poseidon(&[self.creator.hash()?, self.unlock.hash()?])
    }
}

impl ProofInput for EscrowTerms {
    type Circuit = EscrowTerms;

    fn instantiate(&self, allocator: &Allocator) -> Result<EscrowTerms, RelationError> {
        Ok(Self {
            creator: self.creator.instantiate(allocator)?,
            unlock: self.unlock.instantiate(allocator)?,
        })
    }
}
