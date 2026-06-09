pub mod asset;
pub mod data;
pub mod encryption;
pub mod error;
pub mod split;
pub mod transfer;
pub mod utxo;

pub use asset::{AssetRegistry, SOL_ASSET_ID};
pub use data::{Data, DataRecord};
pub use encryption::TransactionEncryption;
pub use error::TransactionError;
pub use solana_address::Address;
pub use utxo::Utxo;

pub const TRANSFER: u8 = 1;
pub const SPLIT: u8 = 2;

pub const VIEW_TAG_LEN: usize = 32;
