use zk_program_sdk::{
    circuit::{poseidon, CircuitVar, DataHash, Owner, Uint, UtxoData},
    CircuitError,
};

#[derive(Clone, Debug)]
pub struct EscrowTerms {
    pub creator: Owner,
    pub unlock: Uint<64>,
}

impl Default for EscrowTerms {
    fn default() -> Self {
        Self {
            creator: Owner::default(),
            unlock: Uint::zero(),
        }
    }
}

impl DataHash for EscrowTerms {
    fn hash(&self) -> Result<CircuitVar, CircuitError> {
        poseidon(&[self.creator.hash()?, self.unlock.hash()?])
    }
}

impl UtxoData for EscrowTerms {
    type Client = crate::EscrowTerms;
}
