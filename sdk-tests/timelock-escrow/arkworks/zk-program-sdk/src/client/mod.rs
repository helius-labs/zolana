mod bytes;
mod owner;
#[cfg(feature = "client")]
mod transaction;
#[cfg(feature = "client")]
mod transfer;
#[cfg(feature = "client")]
mod utxo;

use zolana_keypair::random_blinding;

pub use bytes::Bytes;
pub use owner::Owner;

#[cfg(feature = "client")]
pub use transaction::ZkProgram;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxContext {
    pub blinding_seed: [u8; 32],
    pub output_tree_id: Option<u16>,
}

impl TxContext {
    pub fn new() -> Self {
        Self {
            blinding_seed: random_blinding(),
            output_tree_id: Some(0),
        }
    }

    pub fn with_blinding_seed(mut self, blinding_seed: [u8; 32]) -> Self {
        self.blinding_seed = blinding_seed;
        self
    }

    pub fn with_output_tree_id(mut self, output_tree_id: Option<u16>) -> Self {
        self.output_tree_id = output_tree_id;
        self
    }
}

impl Default for TxContext {
    fn default() -> Self {
        Self::new()
    }
}
