mod bytes;
mod owner;
mod program_owner;
#[cfg(feature = "client")]
mod transaction;
#[cfg(feature = "client")]
mod transfer;
#[cfg(feature = "client")]
mod utxo;

use zolana_keypair::random_blinding;

pub use bytes::Bytes;
pub use owner::Owner;
pub use program_owner::ProgramOwner;

#[cfg(feature = "client")]
pub use transaction::{ProgramTransaction, ZkProgram};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "tsify", derive(tsify::Tsify))]
pub struct TxContext {
    #[cfg_attr(
        feature = "serde",
        serde(with = "zolana_keypair::serde_helpers::bytes")
    )]
    #[cfg_attr(feature = "tsify", tsify(type = "Uint8Array"))]
    pub blinding_seed: [u8; 32],
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    #[cfg_attr(feature = "tsify", tsify(optional))]
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
