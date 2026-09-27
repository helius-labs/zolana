use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    conversion::{Allocator, FromCircuit, Placeholder, ProofInput},
    CircuitError, Owner,
};

use crate::circuit;

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
#[cfg_attr(
    feature = "tsify",
    derive(tsify::Tsify),
    tsify(large_number_types_as_bigints)
)]
pub struct EscrowTerms {
    pub creator: Owner,
    pub unlock: u64,
}

impl zk_program_sdk::circuit::CircuitType for circuit::EscrowTerms {}

impl ProofInput for EscrowTerms {
    type Circuit = circuit::EscrowTerms;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::EscrowTerms, CircuitError> {
        Ok(circuit::EscrowTerms {
            creator: self.creator.instantiate(allocator)?,
            unlock: self.unlock.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for EscrowTerms {
    fn from_circuit(circuit: &circuit::EscrowTerms) -> Result<Self, CircuitError> {
        Ok(Self {
            creator: Owner::from_circuit(&circuit.creator)?,
            unlock: u64::from_circuit(&circuit.unlock)?,
        })
    }
}

impl Placeholder for EscrowTerms {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Self {
            creator: Placeholder::placeholder()?,
            unlock: Placeholder::placeholder()?,
        })
    }
}
