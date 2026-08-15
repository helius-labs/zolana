use thiserror::Error;
use zolana_keypair::KeypairError;

use crate::activities::TurnkeyCurve;

/// Bootstrap and transport failures.
///
/// [`zolana_keypair::ShieldedKeypairTrait`] returns the payload-free
/// [`KeypairError`], so the trait methods collapse everything here into
/// [`KeypairError::SigningFailed`]. This type exists for the fallible async
/// bootstrap, where the caller can still act on the distinction.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TurnkeyKeypairError {
    #[error("Turnkey request failed: {0}")]
    Transport(String),

    /// A policy on the key requires consensus, so the activity is waiting for
    /// approvers rather than failing. Distinct from [`Self::Transport`] because
    /// the caller's response differs: surface it to whoever approves, do not
    /// retry it as a fault.
    ///
    /// Reachable as soon as the key carries a quorum policy, which is the
    /// recommended hardening for the ed25519 rail.
    #[error("Turnkey activity requires approval before it can complete: {0}")]
    RequiresApproval(String),

    /// The activity was still pending after the client's retry budget. The
    /// signature may yet complete, so this is not proof of failure — a caller
    /// that treats it as one can double-submit.
    #[error("Turnkey activity was still pending after {0} attempts")]
    StillPending(usize),

    #[error("Turnkey returned no private key for `{0}`")]
    MissingPrivateKey(String),

    #[error("Turnkey key `{key_id}` is on {actual:?}, expected {expected:?}")]
    CurveMismatch {
        key_id: String,
        expected: TurnkeyCurve,
        actual: TurnkeyCurve,
    },

    #[error("Turnkey returned a malformed {field}: {reason}")]
    MalformedResponse { field: &'static str, reason: String },

    /// The seed is the root of both role secrets, so a signature that does not
    /// verify must never be expanded: it would produce a well-formed identity
    /// that no later check can distinguish from the right one.
    #[error("the derivation-seed signature does not verify against Turnkey's ed25519 public key")]
    SeedSignatureInvalid,

    #[error("Turnkey signed `{key_id}` with a key that does not match its published public key")]
    SignatureKeyMismatch { key_id: String },

    #[error("could not drive the Turnkey request to completion: {0}")]
    Executor(String),

    #[error(transparent)]
    Keypair(#[from] KeypairError),
}

impl TurnkeyKeypairError {
    pub(crate) fn malformed(field: &'static str, reason: impl Into<String>) -> Self {
        Self::MalformedResponse {
            field,
            reason: reason.into(),
        }
    }
}
