use solana_signer::SignerError;
use thiserror::Error;
use zolana_hasher::HasherError;

/// `non_exhaustive` because backends outside this crate match on these: a new
/// failure mode should not be a breaking change for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum KeypairError {
    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid secret key")]
    InvalidSecretKey,

    #[error("derived scalar is zero")]
    ZeroScalar,

    #[error("invalid signature-type prefix: {0}")]
    InvalidSignatureType(u8),

    #[error("signing key is not ed25519")]
    NotEd25519,

    #[error("signing key is not P256")]
    NotP256,

    #[error("a P256 owner has no Solana address")]
    NoSolanaAddress,

    #[error("input would produce the derivation seed; use ShieldedKeypair::from_keypair")]
    DerivationInput,

    #[error("a PDA holds no signing secret; the owning program signs via CPI")]
    PdaCannotSign,

    #[error("derivation seed is {got} bytes, expected {expected} on this rail")]
    InvalidDerivationSeed { got: usize, expected: usize },

    #[error("HKDF expansion failed")]
    Hkdf,

    #[error("signing failed")]
    SigningFailed,

    #[error("poseidon hash failed (code {0})")]
    Poseidon(u32),
}

impl From<HasherError> for KeypairError {
    fn from(error: HasherError) -> Self {
        Self::Poseidon(error.into())
    }
}

impl From<KeypairError> for SignerError {
    fn from(error: KeypairError) -> Self {
        Self::Custom(error.to_string())
    }
}
