use borsh::{BorshDeserialize, BorshSerialize};
use zolana_program::{circuit::CircuitType, Owner};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, CircuitType)]
pub struct EscrowTerms {
    pub creator: Owner,
    pub unlock: u64,
}
