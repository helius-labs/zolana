//! How shielded addresses and their owner projections enter a circuit.

mod address;
mod conversion;
mod owner;
mod owner_input;

use zolana_zk_dsl::{CircuitError, CircuitErrorKind, ProtocolError, ProtocolErrorKind};

pub use address::ShieldedAddressCircuit;
#[doc(hidden)]
pub use conversion::owner;
pub use conversion::OwnerRecords;
pub use owner::{SigningPubkey, UtxoOwner};

/// The owner preimage a proof input carries.
pub mod client {
    pub use super::owner_input::UtxoOwner;
}

#[derive(Debug, thiserror::Error, zolana_zk_dsl::ErrorName)]
#[error_name(prefix = "CircuitError")]
#[non_exhaustive]
pub enum OwnerCircuitErrorKind {
    #[error("invalid proof input: {0}")]
    InvalidOwner(crate::KeypairError),
    #[error("the owner has several viewing addresses and no selected address binding")]
    AmbiguousOwnerAddress,
}

impl ProtocolErrorKind for OwnerCircuitErrorKind {
    fn name(&self) -> &'static str {
        OwnerCircuitErrorKind::name(self)
    }
}

impl From<OwnerCircuitErrorKind> for CircuitError {
    #[track_caller]
    fn from(kind: OwnerCircuitErrorKind) -> Self {
        CircuitErrorKind::Protocol(ProtocolError::new(kind)).into()
    }
}
