use core::fmt;

use zolana_hasher::HasherError;
use zolana_keypair::KeypairError;
use zolana_transaction::TransactionError;
use zolana_zk_dsl::{
    __located_error as located_error, CircuitError, CircuitErrorKind, ProtocolError,
    ProtocolErrorKind, SourceLocation,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotKind {
    Input,
    Output,
    PublicTransfer,
}

impl fmt::Display for SlotKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Input => "input",
            Self::Output => "output",
            Self::PublicTransfer => "public transfer",
        })
    }
}

#[derive(Debug, thiserror::Error, zolana_zk_dsl::ErrorName)]
#[error_name(prefix = "CircuitError")]
#[non_exhaustive]
pub enum ProtocolCircuitErrorKind {
    #[error("a data utxo state cannot be encoded: {0}")]
    StateEncoding(std::io::Error),
    #[error("a state's byte hash differs from its circuit hash")]
    DataHashMismatch,
    #[error("a closed utxo receives no transfer")]
    TransferToClosedUtxo,
    #[error("a data utxo takes an asset only while it is new and holds nothing")]
    AssetOfUsedUtxo,
}

impl ProtocolErrorKind for ProtocolCircuitErrorKind {
    fn name(&self) -> &'static str {
        ProtocolCircuitErrorKind::name(self)
    }
}

impl From<ProtocolCircuitErrorKind> for CircuitError {
    #[track_caller]
    fn from(kind: ProtocolCircuitErrorKind) -> Self {
        CircuitErrorKind::Protocol(ProtocolError::new(kind)).into()
    }
}

#[derive(Debug, thiserror::Error, zolana_zk_dsl::ErrorName)]
#[non_exhaustive]
pub enum ClientErrorKind {
    #[error(transparent)]
    #[error_name(transparent)]
    Circuit(CircuitError),
    #[error("the transaction cannot be built: {0}")]
    Transaction(TransactionError),
    #[error("invalid proof input: {0}")]
    InvalidUtxo(TransactionError),
    #[error("invalid proof input: {0}")]
    InvalidOwner(KeypairError),
    #[error("the output is not owned by the program")]
    NotProgramOutput,
    #[error("the utxo carries no data")]
    NoUtxoData,
    #[error("the utxo data does not decode: {0}")]
    UtxoDataEncoding(std::io::Error),
    #[error("the utxo hash does not commit its data")]
    DataHashMismatch,
    #[error("{kind} slot {index} {problem}")]
    Slot {
        kind: SlotKind,
        index: usize,
        problem: &'static str,
    },
    #[error("a transaction spends at least one input")]
    NoInputs,
    #[error("{0}")]
    TransactionMismatch(&'static str),
    #[error("{0}")]
    Hash(HasherError),
    #[cfg(feature = "wasm")]
    #[error("invalid proof input: {0}")]
    InvalidArgument(String),
    #[cfg(feature = "wasm")]
    #[error("invalid proof input: payer: {0}")]
    InvalidPayer(solana_address::error::ParseAddressError),
    #[cfg(feature = "wasm")]
    #[error("invalid proof input: the sender is not a 99-byte shielded address")]
    SenderLength { found: usize },
    #[cfg(feature = "wasm")]
    #[error("invalid proof input: {0}")]
    InvalidSender(KeypairError),
    #[cfg(feature = "wasm")]
    #[error("a result cannot be converted to a JavaScript value: {0}")]
    JavaScriptConversion(String),
}

located_error!(ClientError, ClientErrorKind);

impl ClientError {
    pub fn location(&self) -> SourceLocation {
        match &self.kind {
            ClientErrorKind::Circuit(error) => error.location(),
            _ => self.location.into(),
        }
    }

    pub fn broken_rule(&self) -> Option<&'static str> {
        self.circuit_error().and_then(CircuitError::broken_rule)
    }

    pub fn circuit_error(&self) -> Option<&CircuitError> {
        match &self.kind {
            ClientErrorKind::Circuit(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CircuitError> for ClientError {
    #[track_caller]
    fn from(error: CircuitError) -> Self {
        ClientErrorKind::Circuit(error).into()
    }
}

impl From<HasherError> for ClientError {
    #[track_caller]
    fn from(error: HasherError) -> Self {
        ClientErrorKind::Hash(error).into()
    }
}

impl fmt::Debug for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let location = SourceLocation::from(self.location);
        match &self.kind {
            ClientErrorKind::Circuit(error) => {
                write!(formatter, "{error:?}\nClientError\n  at {location}")
            }
            kind => write!(formatter, "ClientError: {kind}\n  at {location}"),
        }
    }
}
