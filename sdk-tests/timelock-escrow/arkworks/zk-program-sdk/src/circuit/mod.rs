mod arithmetic;
mod asset;
mod boolean;
mod bytes;
mod circuit_type;
mod compare;
pub(crate) mod field;
pub(crate) mod labels;
mod membership;
mod owner;
mod select;
mod transaction;
mod transfer;
mod uint;
mod utxo;
pub(crate) mod var;

pub use arithmetic::Arithmetic;
pub use asset::Asset;
pub use boolean::Bool;
pub use bytes::Bytes;
pub use circuit_type::{CircuitDefault, CircuitMarker, CircuitType};
pub use compare::Compare;
pub use labels::{CircuitLabel, CircuitSize, FailedConstraint, LabelKind, VariableRole};
pub use membership::{assert_in, is_in};
pub use owner::{Owner, OwnerKey};
pub use select::{one_hot, select_index, Select};
pub use transaction::{CheckedTransaction, ConfidentialTransaction, PublicInputs, TxContext};
pub(crate) use transfer::PublicTransfer;
pub use uint::{Uint, Unsigned};
pub use utxo::{checked_utxo_data, Balance, DataHash, DataUtxo, TokenUtxo, Utxo, UtxoData};
pub use var::{
    constant, from_bits_le, value, zero, Assert, Bits, CircuitSystem, CircuitVar, ConstraintSystem,
    Field,
};
pub use zk_program_sdk_macros::{CircuitType, PublicInputs};

pub use crate::circuit_lib::{hash_bytes, nonzero_hash_chain, poseidon};
use crate::CircuitError;

pub trait Circuit: CircuitType {
    const MARKER: CircuitMarker;

    fn circuit(&self) -> Result<CheckedTransaction, CircuitError>;
}
