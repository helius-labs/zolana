mod asset;
mod boolean;
mod bytes;
mod circuit_type;
mod owner;
mod transaction;
mod transfer;
mod utxo;
mod var;

pub use asset::Asset;
pub use boolean::Bool;
pub use bytes::Bytes;
pub use circuit_type::{CircuitDefault, CircuitMarker, CircuitType};
pub use owner::{Owner, OwnerKey};
pub use transaction::{CheckedTransaction, ConfidentialTransaction, PublicInputs, TxContext};
pub(crate) use transfer::PublicTransfer;
pub use utxo::{checked_utxo_data, Balance, DataHash, DataUtxo, TokenUtxo, Utxo, UtxoData};
pub use var::{constant, value, zero, Assert, CircuitSystem, CircuitVar, ConstraintSystem, Field};
pub use zk_program_sdk_macros::{CircuitType, PublicInputs};

pub use crate::circuit_lib::{hash_bytes, nonzero_hash_chain, poseidon};
use crate::RelationError;

pub trait Circuit: CircuitType {
    const MARKER: CircuitMarker;

    fn circuit(&self) -> Result<CheckedTransaction, RelationError>;
}
