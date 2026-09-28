use core::{fmt, panic::Location};
use std::path::PathBuf;

use ark_relations::gr1cs::SynthesisError;
use zolana_hasher::HasherError;
use zolana_keypair::KeypairError;
use zolana_transaction::TransactionError;

use crate::circuit::{CircuitLabel, CircuitSize, FailedConstraint, LabelKind};

fn apart(label: &Option<Box<CircuitLabel>>) -> String {
    label
        .as_ref()
        .map(|label| format!("; they part at {label}"))
        .unwrap_or_default()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SourceLocation {
    file: &'static str,
    line: u32,
    column: u32,
}

impl SourceLocation {
    pub fn file(&self) -> &'static str {
        self.file
    }

    pub fn line(&self) -> u32 {
        self.line
    }

    pub fn column(&self) -> u32 {
        self.column
    }

    fn of_label(label: &CircuitLabel) -> Self {
        Self {
            file: label.file,
            line: label.line,
            column: label.column,
        }
    }
}

impl From<&'static Location<'static>> for SourceLocation {
    fn from(location: &'static Location<'static>) -> Self {
        Self {
            file: location.file(),
            line: location.line(),
            column: location.column(),
        }
    }
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}:{}", self.file, self.line, self.column)
    }
}

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

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CircuitErrorKind {
    #[error("{0}")]
    RuleBroken(&'static str),
    #[error("{0}")]
    WrongLength(&'static str),
    #[error("a value does not fit in {bits} bits")]
    ValueTooLarge { bits: usize },
    #[error("a check over {bits} bits is too wide; a circuit value holds at most 253 bits")]
    BitWidthTooLarge { bits: usize },
    #[error("a value is neither 0 nor 1")]
    NotZeroOrOne,
    #[error("a division by zero")]
    DivisionByZero,
    #[error("an index is outside an array of {len} items")]
    IndexOutOfBounds { len: usize },
    #[error("the circuit reads the value of a variable; only constants have a value in a circuit")]
    ReadsVariableValue,
    #[error("a hash over {inputs} inputs is not supported")]
    UnsupportedHashInputCount { inputs: usize },
    #[error("{0} is too large for a circuit value")]
    BytesTooLarge(&'static str),
    #[error("invalid proof input: {0}")]
    InvalidOwner(KeypairError),
    #[error("invalid proof input: {0}")]
    InvalidUtxo(TransactionError),
    #[error("a data utxo state cannot be encoded: {0}")]
    StateEncoding(std::io::Error),
    #[error("a state's byte hash differs from its circuit hash")]
    DataHashMismatch,
    #[error("a closed utxo receives no transfer")]
    TransferToClosedUtxo,
    #[error("a data utxo takes an asset only while it is new and holds nothing")]
    AssetOfUsedUtxo,
    #[error("{0}")]
    Hash(HasherError),
    #[error("{0}")]
    Internal(SynthesisError),
}

impl CircuitErrorKind {
    fn name(&self) -> &'static str {
        match self {
            Self::RuleBroken(_) => "CircuitError.RuleBroken",
            Self::WrongLength(_) => "CircuitError.WrongLength",
            Self::ValueTooLarge { .. } => "CircuitError.ValueTooLarge",
            Self::BitWidthTooLarge { .. } => "CircuitError.BitWidthTooLarge",
            Self::NotZeroOrOne => "CircuitError.NotZeroOrOne",
            Self::DivisionByZero => "CircuitError.DivisionByZero",
            Self::IndexOutOfBounds { .. } => "CircuitError.IndexOutOfBounds",
            Self::ReadsVariableValue => "CircuitError.ReadsVariableValue",
            Self::UnsupportedHashInputCount { .. } => "CircuitError.UnsupportedHashInputCount",
            Self::BytesTooLarge(_) => "CircuitError.BytesTooLarge",
            Self::InvalidOwner(_) => "CircuitError.InvalidOwner",
            Self::InvalidUtxo(_) => "CircuitError.InvalidUtxo",
            Self::StateEncoding(_) => "CircuitError.StateEncoding",
            Self::DataHashMismatch => "CircuitError.DataHashMismatch",
            Self::TransferToClosedUtxo => "CircuitError.TransferToClosedUtxo",
            Self::AssetOfUsedUtxo => "CircuitError.AssetOfUsedUtxo",
            Self::Hash(_) => "CircuitError.Hash",
            Self::Internal(_) => "CircuitError.Internal",
        }
    }
}

pub struct CircuitError {
    kind: CircuitErrorKind,
    location: &'static Location<'static>,
}

impl CircuitError {
    #[track_caller]
    pub fn rule_broken(rule: &'static str) -> Self {
        CircuitErrorKind::RuleBroken(rule).into()
    }

    pub fn kind(&self) -> &CircuitErrorKind {
        &self.kind
    }

    pub fn into_kind(self) -> CircuitErrorKind {
        self.kind
    }

    pub fn location(&self) -> SourceLocation {
        self.location.into()
    }

    pub fn broken_rule(&self) -> Option<&'static str> {
        match self.kind {
            CircuitErrorKind::RuleBroken(rule) => Some(rule),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        self.kind.name()
    }

    pub(crate) fn replace_kind(self, kind: CircuitErrorKind) -> Self {
        Self {
            kind,
            location: self.location,
        }
    }

    pub(crate) fn restamp(self, location: &'static Location<'static>) -> Self {
        Self {
            kind: self.kind,
            location,
        }
    }
}

impl From<CircuitErrorKind> for CircuitError {
    #[track_caller]
    fn from(kind: CircuitErrorKind) -> Self {
        Self {
            kind,
            location: Location::caller(),
        }
    }
}

impl From<SynthesisError> for CircuitError {
    #[track_caller]
    fn from(error: SynthesisError) -> Self {
        CircuitErrorKind::Internal(error).into()
    }
}

impl From<HasherError> for CircuitError {
    #[track_caller]
    fn from(error: HasherError) -> Self {
        CircuitErrorKind::Hash(error).into()
    }
}

impl fmt::Display for CircuitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.kind, formatter)
    }
}

impl fmt::Debug for CircuitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "CircuitError: {}\n  at {}",
            self.kind,
            self.location()
        )
    }
}

impl std::error::Error for CircuitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(&self.kind)
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientErrorKind {
    #[error(transparent)]
    Circuit(CircuitError),
    #[error("the transaction cannot be built: {0}")]
    Transaction(TransactionError),
    #[error("invalid proof input: {0}")]
    InvalidUtxo(TransactionError),
    #[error("invalid proof input: {0}")]
    InvalidOwner(KeypairError),
    #[error("the output is not owned by the program")]
    NotProgramOutput,
    #[error("{kind} slot {index} {problem}")]
    Slot {
        kind: SlotKind,
        index: usize,
        problem: &'static str,
    },
    #[error("a transaction spends at least one input")]
    NoInputs,
    #[error("the transaction creates an address, which the SPP transaction builder does not support yet")]
    UnsupportedAddressCreation,
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

impl ClientErrorKind {
    fn name(&self) -> &'static str {
        match self {
            Self::Circuit(error) => error.name(),
            Self::Transaction(_) => "ClientError.Transaction",
            Self::InvalidUtxo(_) => "ClientError.InvalidUtxo",
            Self::InvalidOwner(_) => "ClientError.InvalidOwner",
            Self::NotProgramOutput => "ClientError.NotProgramOutput",
            Self::Slot { .. } => "ClientError.Slot",
            Self::NoInputs => "ClientError.NoInputs",
            Self::UnsupportedAddressCreation => "ClientError.UnsupportedAddressCreation",
            Self::TransactionMismatch(_) => "ClientError.TransactionMismatch",
            Self::Hash(_) => "ClientError.Hash",
            #[cfg(feature = "wasm")]
            Self::InvalidArgument(_) => "ClientError.InvalidArgument",
            #[cfg(feature = "wasm")]
            Self::InvalidPayer(_) => "ClientError.InvalidPayer",
            #[cfg(feature = "wasm")]
            Self::SenderLength { .. } => "ClientError.SenderLength",
            #[cfg(feature = "wasm")]
            Self::InvalidSender(_) => "ClientError.InvalidSender",
            #[cfg(feature = "wasm")]
            Self::JavaScriptConversion(_) => "ClientError.JavaScriptConversion",
        }
    }
}

pub struct ClientError {
    kind: ClientErrorKind,
    location: &'static Location<'static>,
}

impl ClientError {
    pub fn kind(&self) -> &ClientErrorKind {
        &self.kind
    }

    pub fn into_kind(self) -> ClientErrorKind {
        self.kind
    }

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

    pub fn name(&self) -> &'static str {
        self.kind.name()
    }
}

impl From<ClientErrorKind> for ClientError {
    #[track_caller]
    fn from(kind: ClientErrorKind) -> Self {
        Self {
            kind,
            location: Location::caller(),
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

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.kind, formatter)
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

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(&self.kind)
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProverErrorKind {
    #[error(transparent)]
    Circuit(CircuitError),
    #[error("the proof inputs break a rule at {0}")]
    ProofInputsBreakRule(Box<FailedConstraint>),
    #[error(
        "the proof inputs build {proof}, the placeholder builds {setup}{}",
        apart(.first_apart)
    )]
    ShapeDiffers {
        setup: CircuitSize,
        proof: CircuitSize,
        first_apart: Option<Box<CircuitLabel>>,
    },
    #[error("the proof inputs build another constraint than the placeholder at {0}")]
    ConstraintsDiffer(Box<FailedConstraint>),
    #[error("the circuit reads a value while its shape is built")]
    ReadsValueDuringSetup,
    #[error("a circuit has exactly one public input, its public hash")]
    WrongPublicInputCount,
    #[error("the circuit has no private variable {0}")]
    NoSuchVariable(usize),
    #[error("the proof does not verify under these keys")]
    ProofRejected,
    #[error("the proof is corrupt")]
    CorruptProof,
    #[error("the Groth16 keys cannot be read or written: {error}")]
    KeyFile {
        path: PathBuf,
        error: std::io::Error,
    },
    #[cfg(any(feature = "client", feature = "setup"))]
    #[error("the Groth16 keys cannot be read or written: {0}")]
    KeyEncoding(ark_serialize::SerializationError),
    #[cfg(any(feature = "client", feature = "setup"))]
    #[error("the Groth16 key image is malformed: {0}")]
    InvalidKeyImage(&'static str),
    #[cfg(any(feature = "client", feature = "setup"))]
    #[error("the Groth16 key image does not match its sha256 checksum")]
    KeyImageChecksumMismatch,
    #[cfg(any(feature = "client", feature = "setup"))]
    #[error("the Groth16 keys cannot be read or written: {0:?}")]
    VerifyingKeyExport(groth16_solana::errors::Groth16Error),
    #[cfg(any(feature = "client", feature = "setup"))]
    #[error("the Groth16 keys cannot be read or written: {0:?}")]
    InvalidVerifyingKey(groth16_solana::errors::Groth16Error),
    #[error("the zkey is malformed: {0}")]
    InvalidZkey(&'static str),
    #[error("the zkey holds a corrupt {0} value")]
    CorruptZkeyValue(&'static str),
    #[error("the zkey is unfinished: no one has contributed to its setup")]
    UnfinishedZkey,
    #[error("the Groth16 keys belong to another circuit")]
    KeysForAnotherCircuit,
    #[error("the proof inputs build another circuit than the prover's")]
    ProofInputsForAnotherCircuit,
    #[error("the proof inputs are malformed: {0}")]
    InvalidProofInputs(&'static str),
    #[error("a proof input is too large for a circuit value")]
    ProofInputTooLarge,
    #[error("{0}")]
    ExportTooLarge(&'static str),
    #[error("{0}")]
    ExportFailed(&'static str),
    #[error("{0}")]
    Internal(SynthesisError),
}

impl ProverErrorKind {
    fn name(&self) -> &'static str {
        match self {
            Self::Circuit(error) => error.name(),
            Self::ProofInputsBreakRule(_) => "ProverError.ProofInputsBreakRule",
            Self::ShapeDiffers { .. } => "ProverError.ShapeDiffers",
            Self::ConstraintsDiffer(_) => "ProverError.ConstraintsDiffer",
            Self::ReadsValueDuringSetup => "ProverError.ReadsValueDuringSetup",
            Self::WrongPublicInputCount => "ProverError.WrongPublicInputCount",
            Self::NoSuchVariable(_) => "ProverError.NoSuchVariable",
            Self::ProofRejected => "ProverError.ProofRejected",
            Self::CorruptProof => "ProverError.CorruptProof",
            Self::KeyFile { .. } => "ProverError.KeyFile",
            #[cfg(any(feature = "client", feature = "setup"))]
            Self::KeyEncoding(_) => "ProverError.KeyEncoding",
            #[cfg(any(feature = "client", feature = "setup"))]
            Self::InvalidKeyImage(_) => "ProverError.InvalidKeyImage",
            #[cfg(any(feature = "client", feature = "setup"))]
            Self::KeyImageChecksumMismatch => "ProverError.KeyImageChecksumMismatch",
            #[cfg(any(feature = "client", feature = "setup"))]
            Self::VerifyingKeyExport(_) => "ProverError.VerifyingKeyExport",
            #[cfg(any(feature = "client", feature = "setup"))]
            Self::InvalidVerifyingKey(_) => "ProverError.InvalidVerifyingKey",
            Self::InvalidZkey(_) => "ProverError.InvalidZkey",
            Self::CorruptZkeyValue(_) => "ProverError.CorruptZkeyValue",
            Self::UnfinishedZkey => "ProverError.UnfinishedZkey",
            Self::KeysForAnotherCircuit => "ProverError.KeysForAnotherCircuit",
            Self::ProofInputsForAnotherCircuit => "ProverError.ProofInputsForAnotherCircuit",
            Self::InvalidProofInputs(_) => "ProverError.InvalidProofInputs",
            Self::ProofInputTooLarge => "ProverError.ProofInputTooLarge",
            Self::ExportTooLarge(_) => "ProverError.ExportTooLarge",
            Self::ExportFailed(_) => "ProverError.ExportFailed",
            Self::Internal(_) => "ProverError.Internal",
        }
    }

    fn label(&self) -> Option<&CircuitLabel> {
        match self {
            Self::ProofInputsBreakRule(row) | Self::ConstraintsDiffer(row) => row.label.as_ref(),
            Self::ShapeDiffers { first_apart, .. } => first_apart.as_deref(),
            _ => None,
        }
    }
}

pub struct ProverError {
    kind: ProverErrorKind,
    location: &'static Location<'static>,
}

impl ProverError {
    pub fn kind(&self) -> &ProverErrorKind {
        &self.kind
    }

    pub fn into_kind(self) -> ProverErrorKind {
        self.kind
    }

    pub fn location(&self) -> SourceLocation {
        match &self.kind {
            ProverErrorKind::Circuit(error) => error.location(),
            kind => kind
                .label()
                .map(SourceLocation::of_label)
                .unwrap_or_else(|| self.location.into()),
        }
    }

    pub fn broken_rule(&self) -> Option<&'static str> {
        match &self.kind {
            ProverErrorKind::Circuit(error) => error.broken_rule(),
            ProverErrorKind::ProofInputsBreakRule(row) => row
                .label
                .as_ref()
                .filter(|label| label.kind == LabelKind::Check)
                .map(|label| label.text),
            _ => None,
        }
    }

    pub fn circuit_error(&self) -> Option<&CircuitError> {
        match &self.kind {
            ProverErrorKind::Circuit(error) => Some(error),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        self.kind.name()
    }
}

impl ProverError {
    pub(crate) fn at_origin_of(kind: ProverErrorKind, error: &CircuitError) -> Self {
        Self {
            kind,
            location: error.location,
        }
    }
}

impl From<ProverErrorKind> for ProverError {
    #[track_caller]
    fn from(kind: ProverErrorKind) -> Self {
        Self {
            kind,
            location: Location::caller(),
        }
    }
}

impl From<CircuitError> for ProverError {
    #[track_caller]
    fn from(error: CircuitError) -> Self {
        ProverErrorKind::Circuit(error).into()
    }
}

impl From<SynthesisError> for ProverError {
    #[track_caller]
    fn from(error: SynthesisError) -> Self {
        ProverErrorKind::Internal(error).into()
    }
}

impl fmt::Display for ProverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.kind, formatter)
    }
}

impl fmt::Debug for ProverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let location = SourceLocation::from(self.location);
        match &self.kind {
            ProverErrorKind::Circuit(error) => {
                write!(formatter, "{error:?}\nProverError\n  at {location}")
            }
            kind => match kind.label() {
                Some(label) => write!(
                    formatter,
                    "ProverError: {kind}\n  at {}\n  in prover at {location}",
                    SourceLocation::of_label(label)
                ),
                None => write!(formatter, "ProverError: {kind}\n  at {location}"),
            },
        }
    }
}

impl std::error::Error for ProverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(&self.kind)
    }
}
