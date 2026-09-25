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
    #[error("a value does not fit in {0} bits")]
    OutOfRange(usize),
    #[error("a range check over {0} bits covers the whole field")]
    RangeTooWide(usize),
    #[error("a value is neither 0 nor 1")]
    NotBool,
    #[error("the constraint system is unsatisfied at {0}")]
    Unsatisfied(String),
    #[error("the proof does not verify under these keys")]
    ProofRejected,
    #[error("the proof holds a point that is not on the curve")]
    InvalidProofPoint,
    #[error("the Groth16 keys cannot be read or written: {0}")]
    Keys(String),
    #[error("the Groth16 keys belong to another circuit")]
    KeysForAnotherCircuit,
    #[error("the proof inputs build another circuit than the prover's")]
    ProofInputsForAnotherCircuit,
    #[error(transparent)]
    Hasher(#[from] zolana_hasher::HasherError),
    #[error(transparent)]
    Synthesis(#[from] SynthesisError),
}

impl RelationError {
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
