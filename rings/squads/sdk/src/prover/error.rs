//! Errors for the squads prover glue (gated under the `prover` feature).

use std::fmt;

use crate::crypto::CryptoError;

#[derive(Debug)]
pub enum SquadsProverError {
    /// Poseidon hashing failed.
    Poseidon,
    /// A X25519 public key was invalid or noncontributory.
    InvalidPubkey,
    /// `num_keys` is outside the supported set.
    UnsupportedKeyCount(usize),
    /// `(n_inputs, n_outputs)` is outside the supported ring shape set.
    UnsupportedShape(usize, usize),
    /// `inputs[0]` was flagged as a dummy; the first input must be real because
    /// its nullifier seeds the `tx_viewing_sk` KDF.
    DummyFirstInput,
    /// The derived change blinding did not match the sender output blinding (or a
    /// blinding field element was not < 2^248 and could not be encoded in 31 bytes).
    BlindingMismatch,
    /// Proving a squads circuit failed.
    SquadsProver(squads_prover::Error),
    /// The prover response could not be parsed into a proof.
    ProofParse(String),
    /// The SPP prover failed.
    Prover(String),
    /// A withdrawal amount was invalid (change underflow, or a `u64`/`i64`
    /// conversion overflowed).
    InvalidAmount,
    /// A proof or signature byte layout could not be sliced into fixed sizes.
    InvalidProofEncoding,
    /// A multi-input transfer was given inputs that do not all share one asset.
    InputAssetMismatch,
    /// The sender's owner key does not hash to its declared owner identity.
    OwnerIdentityMismatch,
    /// The ring and SPP legs computed different `private_tx_hash` values.
    PrivateTxHashMismatch,
    /// A Ed25519 spend lacked its signature, or a smart-account spend carried one.
    AuthorizationMismatch,
}

impl fmt::Display for SquadsProverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Poseidon => write!(f, "poseidon hashing failed"),
            Self::InvalidPubkey => write!(f, "invalid X25519 public key"),
            Self::UnsupportedKeyCount(n) => write!(f, "unsupported key-encryption key count: {n}"),
            Self::UnsupportedShape(i, o) => {
                write!(f, "unsupported ring shape: {i} inputs, {o} outputs")
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
            Self::SquadsProver(e) => write!(f, "squads prover error: {e}"),
            Self::ProofParse(e) => write!(f, "proof parse error: {e}"),
            Self::Prover(e) => write!(f, "prover error: {e}"),
            Self::InvalidAmount => write!(f, "invalid withdrawal amount"),
            Self::InvalidProofEncoding => write!(f, "invalid proof/signature byte layout"),
            Self::InputAssetMismatch => {
                write!(f, "transfer inputs do not all share one asset")
            }
            Self::OwnerIdentityMismatch => {
                write!(f, "owner key does not match the owner identity")
            }
            Self::PrivateTxHashMismatch => {
                write!(f, "ring and SPP legs disagree on private_tx_hash")
            }
            Self::AuthorizationMismatch => {
                write!(f, "authorization does not match the owner rail")
            }
        }
    }
}

impl std::error::Error for SquadsProverError {}

impl From<squads_prover::Error> for SquadsProverError {
    fn from(e: squads_prover::Error) -> Self {
        Self::SquadsProver(e)
    }
}

impl From<CryptoError> for SquadsProverError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::Poseidon => Self::Poseidon,
        }
    }
}
