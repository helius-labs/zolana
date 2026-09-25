mod asset;
mod bytes;
mod owner;
mod transaction;
mod transfer;
mod utxo;
mod var;

pub use asset::Asset;
pub use bytes::Bytes;
pub use owner::{Owner, OwnerKey};
pub use transaction::{CheckedTransaction, ConfidentialTransaction, PublicInputs, TxContext};
pub(crate) use transfer::PublicTransfer;
pub use utxo::{DataHash, DataUtxo, OutputTokenUtxo, TokenUtxo, Utxo, UtxoData};
pub use var::{constant, value, zero, Assert, CircuitSystem, CircuitVar, ConstraintSystem, Field};

pub use crate::circuit_lib::{hash_bytes, nonzero_hash_chain, poseidon};
use crate::RelationError;

pub trait Circuit {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError>;
}
