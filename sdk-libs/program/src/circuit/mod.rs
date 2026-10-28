mod transaction;
mod transfer;
mod utxo;

pub use spr_keypair::circuit::{ShieldedAddressCircuit, SigningPubkey, UtxoOwner};
pub use spr_macros::{PublicInputs, UtxoState};
pub use spr_transaction::circuit::Utxo;
#[doc(hidden)]
pub use spr_zk_dsl::circuit::{builtins, labels};
pub use spr_zk_dsl::circuit::{
    constant, from_bits_le, system_of, value, zero, Assert, Bool, Bytes, Circuit, CircuitDefault,
    CircuitLabel, CircuitOutput, CircuitSize, CircuitSystem, CircuitType, CircuitVar,
    ConstraintSystem, FailedConstraint, Field, LabelKind, PublicHashOutput, Scope, Select,
    SolanaAddress, Uint, VariableRole, U128, U16, U32, U64, U8,
};
pub use spr_zk_gadgets::{
    assert_in, is_in, nonzero_hash_chain, one_hot, poseidon, select_index, HashBytes,
};

pub(crate) use spr_transaction::circuit::UtxoMeta;
pub use transaction::{
    CheckedTransaction, ConfidentialTransaction, PublicInputs, TransactionItem, TxContext,
};
pub(crate) use transfer::PublicTransfer;
pub use utxo::{DataHash, DataUtxo, NewAddress, TokenUtxos, UniqueDataUtxo, UtxoData, UtxoTrait};
