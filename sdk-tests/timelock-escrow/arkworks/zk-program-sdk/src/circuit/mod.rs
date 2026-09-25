mod transaction;
mod utxo;
mod var;

pub use transaction::{CheckedTransaction, ConfidentialTransaction, PublicInputs, TxContext};
pub use utxo::{DataHash, DataUtxo, OutputTokenUtxo, TokenUtxo, Utxo, UtxoData};
pub use var::{constant, value, zero, Assert, CircuitSystem, CircuitVar, ConstraintSystem, Field};

pub use crate::circuit_lib::{hash_chain4, poseidon};
use crate::RelationError;

pub trait Circuit {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError>;
}
