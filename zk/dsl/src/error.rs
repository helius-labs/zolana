use core::{fmt, panic::Location};
use std::path::PathBuf;

use ark_relations::gr1cs::SynthesisError;
use zolana_hasher::HasherError;

use crate::circuit::{CircuitLabel, CircuitSize, FailedConstraint, LabelKind};

// Keep caller capture, accessors and error chaining identical for all layers.
#[doc(hidden)]
#[macro_export]
macro_rules! __located_error {
    ($name:ident, $kind:ident) => {
        pub struct $name {
            kind: $kind,
            location: &'static ::core::panic::Location<'static>,
        }
        impl $name {
            pub fn kind(&self) -> &$kind {
                &self.kind
            }
            pub fn into_kind(self) -> $kind {
                self.kind
            }
            pub fn name(&self) -> &'static str {
                self.kind.name()
            }
        }
        impl From<$kind> for $name {
            #[track_caller]
            fn from(kind: $kind) -> Self {
                Self {
                    kind,
                    location: ::core::panic::Location::caller(),
                }
            }
        }
        impl ::core::fmt::Display for $name {
            fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Display::fmt(&self.kind, formatter)
            }
        }
        impl std::error::Error for $name {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                std::error::Error::source(&self.kind)
            }
        }
    };
}

use crate::__located_error as located_error;

fn apart(label: &Option<Box<CircuitLabel>>) -> String {
    label
        .as_ref()
        .map(|label| format!("; they part at {label}"))
        .unwrap_or_default()
}

/// Coordinates can come from a caller or a circuit label. Core Location has
/// no constructor for the latter, so labels need this small value type.
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

#[derive(Debug, thiserror::Error, zolana_zk_macros::ErrorName)]
#[non_exhaustive]
pub enum CircuitErrorKind {
    #[error("{0}")]
    RuleBroken(&'static str),
    #[error("{0}")]
    WrongLength(&'static str),
    #[error("{field} takes at most {max} items, {given} given")]
    TooManyItems {
        field: &'static str,
        max: usize,
        given: usize,
    },
    #[error("{field} takes at least {min} items, {given} given")]
    TooFewItems {
        field: &'static str,
        min: usize,
        given: usize,
    },
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
    #[error(transparent)]
    #[error_name(transparent)]
    Protocol(ProtocolError),
    #[error("{0}")]
    Hash(HasherError),
    #[error("{0}")]
    Internal(SynthesisError),
}

/// A circuit error kind defined by a crate built on the DSL. Its name keeps the
/// `CircuitError.` prefix, so callers see one error family whichever crate
/// raised it.
pub trait ProtocolErrorKind: std::error::Error + Send + Sync + 'static {
    fn name(&self) -> &'static str;
}

pub struct ProtocolError(Box<dyn ProtocolErrorKind>);

impl ProtocolError {
    pub fn new(kind: impl ProtocolErrorKind) -> Self {
        Self(Box::new(kind))
    }

    pub fn name(&self) -> &'static str {
        self.0.name()
    }

    pub fn kind<T: ProtocolErrorKind>(&self) -> Option<&T> {
        let error: &(dyn std::error::Error + 'static) = &*self.0;
        error.downcast_ref()
    }
}

impl fmt::Debug for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, formatter)
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

located_error!(CircuitError, CircuitErrorKind);

impl CircuitError {
    #[track_caller]
    pub fn rule_broken(rule: &'static str) -> Self {
        CircuitErrorKind::RuleBroken(rule).into()
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

    pub fn protocol_kind<T: ProtocolErrorKind>(&self) -> Option<&T> {
        match &self.kind {
            CircuitErrorKind::Protocol(error) => error.kind(),
            _ => None,
        }
    }

    #[doc(hidden)]
    pub fn replace_kind(self, kind: CircuitErrorKind) -> Self {
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

#[derive(Debug, thiserror::Error, zolana_zk_macros::ErrorName)]
#[non_exhaustive]
pub enum ProverErrorKind {
    #[error(transparent)]
    #[error_name(transparent)]
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
    #[error("the circuit allocates another number of public inputs than its output binds")]
    WrongPublicInputCount,
    #[error("a proof has {count} public inputs; the verifier takes at most {max}")]
    TooManyPublicInputs { count: usize, max: usize },
    #[error("the circuit has no private variable {0}")]
    NoSuchVariable(usize),
    #[error("the proof does not verify under these keys")]
    ProofRejected,
    #[error("the proof is corrupt")]
    CorruptProof,
    #[error("the Groth16 key file {} cannot be read or written: {error}", path.display())]
    KeyFile {
        path: PathBuf,
        error: std::io::Error,
    },
    #[cfg(feature = "client")]
    #[error("the Groth16 key image is malformed: {0}")]
    InvalidKeyImage(&'static str),
    #[cfg(feature = "client")]
    #[error("the Groth16 key image does not match its sha256 checksum")]
    KeyImageChecksumMismatch,
    #[error("production export requires an imported ceremony zkey; this key has no verified ceremony provenance")]
    ProductionKeyRequired,
    #[cfg(feature = "setup")]
    #[error("the verifying key cannot be exported: {0}")]
    VerifyingKeyExport(groth16_solana::vk::circom::VkParseError),
    #[cfg(feature = "client")]
    #[error("the Groth16 keys cannot be read or written: {0:?}")]
    InvalidVerifyingKey(groth16_solana::errors::Groth16Error),
    #[error("the zkey is malformed: {0}")]
    InvalidZkey(&'static str),
    #[error("the zkey holds a corrupt {0} value")]
    CorruptZkeyValue(&'static str),
    #[error("the zkey is unfinished: no one has contributed to its setup")]
    UnfinishedZkey,
    #[error("the r1cs is malformed: {0}")]
    InvalidR1cs(&'static str),
    #[error("the r1cs file {} cannot be read: {error}", path.display())]
    R1csFile {
        path: PathBuf,
        error: std::io::Error,
    },
    #[error("the Groth16 keys belong to another circuit")]
    KeysForAnotherCircuit,
    #[error("the proof inputs build another circuit than the prover's")]
    ProofInputsForAnotherCircuit,
    #[error("the proof inputs are malformed: {0}")]
    InvalidProofInputs(&'static str),
    #[error("a proof input is too large for a circuit value")]
    ProofInputTooLarge,
    #[cfg(feature = "wasm")]
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[cfg(feature = "wasm")]
    #[error("a result cannot be converted to a JavaScript value: {0}")]
    JavaScriptConversion(String),
    #[error("{0}")]
    ExportTooLarge(&'static str),
    #[error("{0}")]
    ExportFailed(&'static str),
    #[error("{0}")]
    Internal(SynthesisError),
}

impl ProverErrorKind {
    fn label(&self) -> Option<&CircuitLabel> {
        match self {
            Self::ProofInputsBreakRule(row) | Self::ConstraintsDiffer(row) => row.label.as_ref(),
            Self::ShapeDiffers { first_apart, .. } => first_apart.as_deref(),
            _ => None,
        }
    }
}

located_error!(ProverError, ProverErrorKind);

impl ProverError {
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
}

#[cfg(feature = "client")]
impl ProverError {
    pub(crate) fn at_origin_of(kind: ProverErrorKind, error: &CircuitError) -> Self {
        Self {
            kind,
            location: error.location,
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
