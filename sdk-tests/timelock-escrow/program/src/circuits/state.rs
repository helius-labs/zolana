use borsh::{BorshDeserialize, BorshSerialize};
use spr_program::{circuit::UtxoState, UtxoOwner};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState)]
pub struct EscrowTerms {
    pub creator: UtxoOwner,
    pub unlock: u64,
}
