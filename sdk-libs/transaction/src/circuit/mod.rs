//! How mints and wallet utxos enter a circuit: the address and utxo circuit
//! types and their conversions.

mod conversion;
mod utxo;

use zolana_zk_dsl::{CircuitError, CircuitErrorKind, ProtocolError, ProtocolErrorKind};

pub use conversion::{MintRecords, UtxoRecords};
pub use utxo::Utxo;
#[doc(hidden)]
pub use utxo::{SpentInput, UtxoMeta};
pub use zolana_zk_dsl::circuit::SolanaAddress;

#[derive(Debug, thiserror::Error, zolana_zk_dsl::ErrorName)]
#[error_name(prefix = "CircuitError")]
#[non_exhaustive]
pub enum UtxoCircuitErrorKind {
    #[error("invalid proof input: {0}")]
    InvalidUtxo(crate::error::TransactionError),
}

impl ProtocolErrorKind for UtxoCircuitErrorKind {
    fn name(&self) -> &'static str {
        UtxoCircuitErrorKind::name(self)
    }
}

impl From<UtxoCircuitErrorKind> for CircuitError {
    #[track_caller]
    fn from(kind: UtxoCircuitErrorKind) -> Self {
        CircuitErrorKind::Protocol(ProtocolError::new(kind)).into()
    }
}
