use ark_relations::r1cs::SynthesisError;

#[derive(Debug, thiserror::Error)]
pub enum RelationError {
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
    #[error(transparent)]
    Hasher(#[from] zolana_hasher::HasherError),
    #[error(transparent)]
    Synthesis(#[from] SynthesisError),
}

impl From<RelationError> for SynthesisError {
    fn from(error: RelationError) -> Self {
        match error {
            RelationError::Synthesis(error) => error,
            _ => SynthesisError::Unsatisfiable,
        }
    }
}
