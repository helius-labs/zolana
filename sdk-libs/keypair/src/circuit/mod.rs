//! How shielded addresses enter a circuit: the owner circuit type, the owner
//! preimage a proof input carries, and their conversions.

mod conversion;
mod owner;
mod owner_input;

use zolana_zk_dsl::{CircuitError, CircuitErrorKind, ProtocolError, ProtocolErrorKind};

#[doc(hidden)]
pub use conversion::owner;
pub use conversion::OwnerRecords;
pub use owner::{Owner, OwnerKey};

/// The owner preimage a proof input carries.
pub mod client {
    pub use super::owner_input::Owner;
}

#[derive(Debug, thiserror::Error, zolana_zk_dsl::ErrorName)]
#[error_name(prefix = "CircuitError")]
#[non_exhaustive]
pub enum OwnerCircuitErrorKind {
    #[error("invalid proof input: {0}")]
    InvalidOwner(crate::KeypairError),
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
