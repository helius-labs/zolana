//! Errors for the squads prover glue (gated under the `prover` feature).

use std::fmt;

use crate::crypto::CryptoError;

#[derive(Debug)]
pub enum SquadsProverError {
    /// Poseidon hashing failed.
    Poseidon,
    /// A P-256 scalar (viewing/ephemeral) was not a valid curve scalar.
    InvalidScalar,
    /// A P-256 public key was not valid SEC1.
    InvalidPubkey,
    /// `num_keys` is outside the supported set.
    UnsupportedKeyCount(usize),
    /// `(n_inputs, n_outputs)` is outside the supported zone shape set.
    UnsupportedShape(usize, usize),
    /// `inputs[0]` was flagged as a dummy; the first input must be real because
    /// its nullifier seeds the `tx_viewing_sk` KDF.
    DummyFirstInput,
    /// The derived change blinding did not match the sender output blinding (or a
    /// blinding field element was not < 2^248 and could not be encoded in 31 bytes).
    BlindingMismatch,
    /// HTTP request to the prover server failed.
    ProverServer(String),
    /// The prover response could not be parsed into a proof.
    ProofParse(String),
    /// Groth16 proof compression failed.
    ProofCompress(String),
    /// Spawning / connecting to the prover server failed.
    Prover(String),
    /// A withdrawal amount was invalid (change underflow, or a `u64`/`i64`
    /// conversion overflowed).
    InvalidAmount,
    /// A proof or signature byte layout could not be sliced into fixed sizes.
    InvalidProofEncoding,
    /// A multi-input transfer was given inputs that do not all share one asset.
    InputAssetMismatch,
}

impl fmt::Display for SquadsProverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Poseidon => write!(f, "poseidon hashing failed"),
            Self::InvalidScalar => write!(f, "invalid P-256 scalar"),
            Self::InvalidPubkey => write!(f, "invalid P-256 public key"),
            Self::UnsupportedKeyCount(n) => write!(f, "unsupported key-encryption key count: {n}"),
            Self::UnsupportedShape(i, o) => {
                write!(f, "unsupported zone shape: {i} inputs, {o} outputs")
            }
            Self::DummyFirstInput => {
                write!(
                    f,
                    "inputs[0] cannot be a dummy: it seeds the tx_viewing_sk KDF"
                )
            }
            Self::BlindingMismatch => {
                write!(f, "change blinding mismatch or non-encodable blinding")
            }
            Self::ProverServer(e) => write!(f, "prover server error: {e}"),
            Self::ProofParse(e) => write!(f, "proof parse error: {e}"),
            Self::ProofCompress(e) => write!(f, "proof compression error: {e}"),
            Self::Prover(e) => write!(f, "prover error: {e}"),
            Self::InvalidAmount => write!(f, "invalid withdrawal amount"),
            Self::InvalidProofEncoding => write!(f, "invalid proof/signature byte layout"),
            Self::InputAssetMismatch => {
                write!(f, "transfer inputs do not all share one asset")
            }
        }
    }
}

impl std::error::Error for SquadsProverError {}

impl From<CryptoError> for SquadsProverError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::Poseidon => Self::Poseidon,
            CryptoError::InvalidScalar => Self::InvalidScalar,
        }
    }
}
