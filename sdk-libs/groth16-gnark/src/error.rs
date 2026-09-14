use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("key bytes end after {0} bytes")]
    Truncated(usize),
    #[error("{0} bytes left after the key")]
    TrailingBytes(usize),
    #[error("scalar at byte {0} is not canonical")]
    NonCanonicalScalar(usize),
    #[error("base field element at byte {0} is not canonical")]
    NonCanonicalCoordinate(usize),
    #[error("point at byte {0} uses the uncompressed encoding")]
    UncompressedPoint(usize),
    #[error("point at byte {0} has no y for its x")]
    PointNotOnCurve(usize),
    #[error("infinity marker at byte {0} carries data")]
    MalformedInfinity(usize),
    #[error("domain of size {0} is not a power of two")]
    DomainSize(u64),
    #[error("domain fields disagree with the cardinality")]
    DomainInconsistent,
    #[error("infinity bitmaps disagree with the point counts")]
    InfinityCounts,
    #[error("{0} BSB22 commitment keys, only plain Groth16 keys are supported")]
    CommitmentKeysUnsupported(u32),
    #[error("assignment has {wires} wires, the key has {expected}")]
    WireCount { wires: usize, expected: usize },
    #[error("assignment vectors a, b, c differ in length")]
    UnevenAssignment,
    #[error("{0} constraints exceed the domain")]
    TooManyConstraints(usize),
    #[error("{0} public wires exceed the wire count")]
    PublicCount(usize),
    #[error("assignment blob is malformed at byte {0}")]
    MalformedAssignment(usize),
}
