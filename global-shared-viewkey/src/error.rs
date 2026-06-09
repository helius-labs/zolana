use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GlobalSharedViewKeyError {
    #[error("cryptography error: {0}")]
    Crypto(&'static str),

    #[error("shamir error: {0}")]
    Shamir(&'static str),

    #[error("invalid configuration: {0}")]
    InvalidConfig(&'static str),

    #[error("share signature verification failed")]
    BadSignature,

    #[error("quorum not met: {got} of {needed} entities could contribute their outer share")]
    QuorumNotMet { needed: usize, got: usize },

    #[error("share blob is malformed")]
    ShortBlob,

    #[error("reconstructed scalar is not a valid key")]
    InvalidReconstructedKey,
}
