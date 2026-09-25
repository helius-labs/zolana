use zk_program_sdk::{
    circuit::{poseidon, zero, CircuitVar, DataHash, UtxoData},
    RelationError,
};

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

impl UtxoData for EscrowTerms {
    type Client = crate::EscrowTerms;
}
