use super::{constant, poseidon, Asset, Bytes, CircuitVar, Uint};
use crate::CircuitError;

#[derive(Clone, Debug)]
pub(crate) struct PublicTransfer {
    pub(crate) asset: Asset,
    pub(crate) is_deposit: bool,
    pub(crate) amount: Uint<64>,
    pub(crate) account: Bytes<32>,
}

impl PublicTransfer {
    pub(crate) fn hash(&self) -> Result<CircuitVar, CircuitError> {
        poseidon(&[
            self.asset.hash()?,
            self.amount.var(),
            constant(u64::from(self.is_deposit)),
            self.account.hash_bytes()?,
        ])
    }
}
