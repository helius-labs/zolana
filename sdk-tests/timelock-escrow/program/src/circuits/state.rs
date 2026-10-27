use borsh::{BorshDeserialize, BorshSerialize};
use zolana_program::{input, UtxoState, UtxoOwner};

#[input(no_derive)]
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState)]
pub struct EscrowTerms {
    pub creator: UtxoOwner,
    pub unlock: u64,
}
