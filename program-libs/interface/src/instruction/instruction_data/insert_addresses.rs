use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct InsertAddressesData {
    pub addresses: Vec<[u8; 32]>,
}
