pub(crate) mod builtins;
mod circuit_type;
pub(crate) mod labels;
pub(crate) mod output;
mod protocol;

pub use builtins::{
    assert_in, constant, from_bits_le, is_in, nonzero_hash_chain, one_hot, poseidon, select_index,
    value, zero, Assert, Bool, Bytes, CircuitSystem, CircuitVar, ConstraintSystem, Field, Select,
    Uint, U128, U16, U32, U64, U8,
};
pub use circuit_type::{CircuitDefault, CircuitType};
pub use labels::{CircuitLabel, CircuitSize, FailedConstraint, LabelKind, VariableRole};
pub use output::CircuitOutput;
pub(crate) use protocol::PublicTransfer;
pub use protocol::{
    Asset, CheckedTransaction, ConfidentialTransaction, DataHash, DataUtxo, Owner, OwnerKey,
    PublicInputs, TokenUtxos, TxContext, UniqueDataUtxo, Utxo, UtxoData, UtxoTrait,
};
pub use zolana_macros::{CircuitType, PublicInputs};

use crate::CircuitError;

pub trait Circuit: CircuitType {
    type Output: CircuitOutput;

    fn circuit(&self) -> Result<Self::Output, CircuitError>;
}

pub(crate) use protocol::UtxoMeta;
