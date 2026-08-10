use thiserror::Error;

use crate::crypto::CryptoError;

#[derive(Debug, Error)]
pub enum SquadsProverError {
    /// Poseidon hashing failed.
    #[error("poseidon hashing failed")]
    Poseidon,
    /// A P-256 scalar (viewing/ephemeral) was not a valid curve scalar.
    #[error("invalid P-256 scalar")]
    InvalidScalar,
    /// A P-256 public key was not valid SEC1.
    #[error("invalid P-256 public key")]
    InvalidPubkey,
    /// `num_keys` is outside the supported set.
    #[error("unsupported key-encryption key count: {0}")]
    UnsupportedKeyCount(usize),
    /// `(n_inputs, n_outputs)` is outside the supported ring shape set.
    #[error("unsupported ring shape: {0} inputs, {1} outputs")]
    UnsupportedShape(usize, usize),
    /// `inputs[0]` was flagged as a dummy. The first input must be real because
    /// its nullifier seeds the `tx_viewing_sk` KDF.
    #[error("inputs[0] cannot be a dummy: it seeds the tx_viewing_sk KDF")]
    DummyFirstInput,
    /// The derived change blinding did not match the sender output blinding (or a
    /// blinding field element was not < 2^248 and could not be encoded in 31 bytes).
    #[error("change blinding mismatch or non-encodable blinding")]
    BlindingMismatch,
    /// HTTP request to the prover server failed.
    #[error("prover server error: {0}")]
    ProverServer(String),
    /// Squads proof inputs carry wallet secrets, so only a loopback prover may
    /// see them.
    #[error(
        "squads proof inputs carry wallet secrets and require a local prover, not {server_address}"
    )]
    RequiresLocalProver { server_address: String },
    /// The configured prover address is not a URL.
    #[error("prover server URL is malformed: {server_address}")]
    InvalidProverUrl { server_address: String },
    /// The prove request could not be serialized.
    #[error("prove request serialization failed: {0}")]
    RequestSerialize(String),
    /// The prover response could not be parsed into a proof.
    #[error("proof parse error: {0}")]
    ProofParse(String),
    /// Groth16 proof compression failed.
    #[error("proof compression error: {0}")]
    ProofCompress(String),
    /// A proved value did not match the value rebuilt from the request.
    #[error("proof cross-check failed: {0}")]
    ProofValidation(String),
    /// A withdrawal amount was invalid (change underflow, or a `u64`/`i64`
    /// conversion overflowed).
    #[error("invalid withdrawal amount")]
    InvalidAmount,
    /// A proof or signature byte layout could not be sliced into fixed sizes.
    #[error("invalid proof/signature byte layout")]
    InvalidProofEncoding,
    /// A multi-input transfer was given inputs that do not all share one asset.
    #[error("transfer inputs do not all share one asset")]
    InputAssetMismatch,
    /// The leg count is outside the supported fold set.
    #[error("unsupported fold leg count: {0}")]
    UnsupportedLegCount(usize),
    /// A folded leg carried a proposal. A proposal commits to one operation, so
    /// a run under one would settle it once per leg.
    #[error("a folded leg cannot carry a proposal")]
    FoldedProposal,
    /// The named leg spends a different account than the first leg.
    #[error("leg {0} spends another account")]
    FoldedSenderMismatch(usize),
    /// The named leg pays a different recipient than the first leg.
    #[error("leg {0} pays another recipient")]
    FoldedRecipientMismatch(usize),
    /// A fixed-width slot the proven shape requires was absent.
    #[error("a required fixed-width slot was absent")]
    MissingSlot,
}

impl From<CryptoError> for SquadsProverError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::Poseidon => Self::Poseidon,
            CryptoError::InvalidScalar => Self::InvalidScalar,
            CryptoError::InvalidPubkey => Self::InvalidPubkey,
        }
    }
}
