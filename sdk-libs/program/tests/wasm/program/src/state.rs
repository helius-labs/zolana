use borsh::{BorshDeserialize, BorshSerialize};
use zolana_program::{circuit::UtxoState, Owner};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState)]
pub struct EscrowTerms {
    pub creator: Owner,
    pub unlock: u64,
}
