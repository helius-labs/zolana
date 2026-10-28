use crate::{CircuitError, Field, hash_bytes, poseidon};

#[derive(Clone, Debug)]
pub struct PublicTransfer {
    pub asset: [u8; 32], pub is_deposit: bool, pub amount: u64, pub account: [u8; 32],
}
impl PublicTransfer {
    pub fn hash(&self) -> Result<Field, CircuitError> {
        poseidon(&[hash_bytes(&self.asset)?, Field::from(self.amount), Field::from(self.is_deposit), hash_bytes(&self.account)?])
    }
}
