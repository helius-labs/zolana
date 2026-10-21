use crate::{
    circuit::{constant, poseidon, CircuitVar, HashBytes, SolanaAddress, Uint},
    CircuitError,
};

#[derive(Clone, Debug)]
pub(crate) struct PublicTransfer {
    pub(crate) asset: SolanaAddress,
    pub(crate) is_deposit: bool,
    pub(crate) amount: Uint<64>,
    pub(crate) account: SolanaAddress,
}

impl PublicTransfer {
    pub(crate) fn hash(&self) -> Result<CircuitVar, CircuitError> {
        poseidon(&[
            self.asset.hash_bytes()?,
            self.amount.var(),
            constant(u64::from(self.is_deposit)),
            self.account.hash_bytes()?,
        ])
    }
}
