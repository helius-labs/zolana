#[doc(hidden)]
pub mod builtins;
mod circuit_type;
#[doc(hidden)]
pub mod labels;
pub(crate) mod output;

pub use builtins::{
    constant, from_bits_le, value, zero, Assert, Bool, Bytes, CircuitSystem, CircuitVar,
    ConstraintSystem, Field, Select, Uint, U128, U16, U32, U64, U8,
};
pub use circuit_type::{CircuitDefault, CircuitType};
pub use labels::{CircuitLabel, CircuitSize, FailedConstraint, LabelKind, VariableRole};
#[cfg(feature = "client")]
pub(crate) use output::Binding;
pub use output::{CircuitOutput, PublicHashOutput};
pub use zolana_zk_macros::CircuitType;

use crate::CircuitError;

pub trait Circuit: CircuitType {
    type Output: CircuitOutput;

    fn circuit(&self) -> Result<Self::Output, CircuitError>;
}
