#[cfg(feature = "client")]
mod transaction;
#[cfg(feature = "client")]
mod utxo;

use zolana_keypair::{random_blinding, ShieldedAddress};

#[cfg(feature = "client")]
pub use transaction::ZkProgram;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxContext {
    pub first_nullifier: [u8; 32],
    pub blinding_seed: [u8; 32],
    pub output_tree_id: u16,
    pub sender: ShieldedAddress,
}

impl TxContext {
    pub fn new(first_nullifier: [u8; 32], output_tree_id: u16, sender: ShieldedAddress) -> Self {
        Self {
            first_nullifier,
            blinding_seed: random_blinding(),
            output_tree_id,
            sender,
        }
    }

    pub fn with_blinding_seed(mut self, blinding_seed: [u8; 32]) -> Self {
        self.blinding_seed = blinding_seed;
        self
    }
}
