pub(crate) mod builtins;
mod circuit_type;
pub(crate) mod labels;
mod protocol;

pub use builtins::{
    assert_in, constant, from_bits_le, is_in, nonzero_hash_chain, one_hot, poseidon, select_index,
    value, zero, Assert, Bits, Bool, Bytes, CircuitSystem, CircuitVar, ConstraintSystem, Field,
    Select, Uint, U128, U16, U32, U64, U8,
};
pub use circuit_type::{CircuitDefault, CircuitType};
pub use labels::{CircuitLabel, CircuitSize, FailedConstraint, LabelKind, VariableRole};
pub(crate) use protocol::PublicTransfer;
pub use protocol::{
    checked_utxo_data, Asset, CheckedTransaction, ConfidentialTransaction, DataHash, DataUtxo,
    Owner, OwnerKey, PublicInputs, TokenUtxo, TxContext, UniqueDataUtxo, Utxo, UtxoData, UtxoMeta,
    UtxoTrait,
};
pub use zk_program_sdk_macros::{CircuitType, PublicInputs};

use crate::CircuitError;

pub trait Circuit: CircuitType {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError>;
}

pub trait Constraints: CircuitType {
    fn constraints(&self) -> Result<(), CircuitError>;
}
