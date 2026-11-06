use borsh::{BorshDeserialize, BorshSerialize};
use spr_program::{input, UtxoOwner, UtxoState};

#[input]
#[derive(
    Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState, spr_program::ClientInputs,
)]
pub struct EscrowTerms {
    pub creator: UtxoOwner,
    pub unlock: u64,
}
