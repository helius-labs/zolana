use ark_relations::r1cs::SynthesisError;

#[derive(Debug, thiserror::Error)]
pub enum RelationError {
    // TODO: rename to CircuitError
    #[error("{0}")]
    Violated(&'static str),
    #[error("{kind} slot {slot} {problem}")]
    Slot {
        kind: &'static str,
        slot: usize,
        problem: &'static str,
    },
    #[error("poseidon over {0} inputs is not supported")]
    PoseidonArity(usize),
    #[error("{0} is not a canonical field element")]
    NonCanonical(&'static str),
    #[error("invalid proof input: {0}")]
    InvalidInput(String),
    #[error("the SPP proof inputs cannot be built: {0}")]
    Spp(String),
    #[error("{0}")]
    Conversion(&'static str),
    #[error("a data utxo state cannot be encoded: {0}")]
    StateEncoding(String),
    #[error("a state's byte hash differs from its circuit hash")]
    DataHashMismatch,
    #[error("a value does not fit in {0} bits")]
    OutOfRange(usize),
    #[error("a range check over {0} bits covers the whole field")]
    RangeTooWide(usize),
    #[error("a value is neither 0 nor 1")]
    NotBool,
    #[error("an operation on {0}-bit integers overflows")]
    Overflow(usize),
    #[error("a subtraction on {0}-bit integers underflows")]
    Underflow(usize),
    #[error("a division by zero")]
    DivisionByZero,
    #[error("an index is outside an array of {0} items")]
    IndexOutOfBounds(usize),
    #[error("the constraint system is unsatisfied at {0}")]
    Unsatisfied(String),
    #[error("the proof does not verify under these keys")]
    ProofRejected,
    #[error("the proof holds a point that is not on the curve")]
    InvalidProofPoint,
    #[error("the Groth16 keys cannot be read or written: {0}")]
    Keys(String),
    #[error("the zkey is malformed: {0}")]
    InvalidZkey(&'static str),
    #[error("the zkey holds a {0} point that is not a valid curve point")]
    InvalidKeyPoint(&'static str),
    #[error("the zkey has no phase-2 contribution, so its delta equals gamma")]
    UncontributedZkey,
    #[error("the Groth16 keys belong to another circuit")]
    KeysForAnotherCircuit,
    #[error("the proof inputs build another circuit than the prover's")]
    ProofInputsForAnotherCircuit,
    #[error("the proof inputs are malformed: {0}")]
    InvalidProofInputs(&'static str),
    #[error("a result cannot be converted to a JavaScript value: {0}")]
    ToJs(String),
    #[error(transparent)]
    Hasher(#[from] zolana_hasher::HasherError),
    #[error(transparent)]
    Synthesis(#[from] SynthesisError),
}

impl RelationError {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Violated(_) => "Violated",
            Self::Slot { .. } => "Slot",
            Self::PoseidonArity(_) => "PoseidonArity",
            Self::NonCanonical(_) => "NonCanonical",
            Self::InvalidInput(_) => "InvalidInput",
            Self::Spp(_) => "Spp",
            Self::Conversion(_) => "Conversion",
            Self::StateEncoding(_) => "StateEncoding",
            Self::DataHashMismatch => "DataHashMismatch",
            Self::OutOfRange(_) => "OutOfRange",
            Self::RangeTooWide(_) => "RangeTooWide",
            Self::NotBool => "NotBool",
            Self::Overflow(_) => "Overflow",
            Self::Underflow(_) => "Underflow",
            Self::DivisionByZero => "DivisionByZero",
            Self::IndexOutOfBounds(_) => "IndexOutOfBounds",
            Self::Unsatisfied(_) => "Unsatisfied",
            Self::ProofRejected => "ProofRejected",
            Self::InvalidProofPoint => "InvalidProofPoint",
            Self::Keys(_) => "Keys",
            Self::InvalidZkey(_) => "InvalidZkey",
            Self::InvalidKeyPoint(_) => "InvalidKeyPoint",
            Self::UncontributedZkey => "UncontributedZkey",
            Self::KeysForAnotherCircuit => "KeysForAnotherCircuit",
            Self::ProofInputsForAnotherCircuit => "ProofInputsForAnotherCircuit",
            Self::InvalidProofInputs(_) => "InvalidProofInputs",
            Self::ToJs(_) => "ToJs",
            Self::Hasher(_) => "Hasher",
            Self::Synthesis(_) => "Synthesis",
        }
    }

    pub(crate) fn input(error: impl core::fmt::Display) -> Self {
        Self::InvalidInput(error.to_string())
    }

    #[cfg(feature = "client")]
    pub(crate) fn spp(error: impl core::fmt::Display) -> Self {
        Self::Spp(error.to_string())
    }

    #[cfg(any(feature = "client", feature = "setup"))]
    pub(crate) fn keys(error: impl core::fmt::Display) -> Self {
        Self::Keys(error.to_string())
    }
}

impl From<RelationError> for SynthesisError {
    fn from(error: RelationError) -> Self {
        match error {
            RelationError::Synthesis(error) => error,
            _ => SynthesisError::Unsatisfiable,
        }
    }
}
