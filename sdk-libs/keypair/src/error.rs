use solana_signer::SignerError;
use thiserror::Error;
use zolana_hasher::HasherError;

/// `non_exhaustive` because backends outside this crate match on these: a new
/// failure mode should not be a breaking change for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum KeypairError {
    #[error("X25519 agreement with a low-order key")]
    NonContributoryKey,
    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid shielded address")]
    InvalidShieldedAddress,

    #[error("invalid secret key")]
    InvalidSecretKey,

    #[error("invalid signature-type prefix: {0}")]
    InvalidSignatureType(u8),

    #[error("signing key is not ed25519")]
    NotEd25519,

    #[error("owner has no Solana address")]
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

    #[error("ring payment request does not start with zolana:")]
    InvalidRingAddressScheme,

    #[error("ring address is not base58")]
    InvalidRingAddressBase58,

    #[error("ring address has the wrong length")]
    InvalidRingAddressLength,

    #[error("unknown ring address version {0}")]
    UnknownRingAddressVersion(u8),

    #[error("ring address checksum mismatch")]
    InvalidRingAddressChecksum,

    #[error("ring address names {0} pairing rows, at most 4 fit")]
    InvalidRingAddressPairing(usize),

    #[error("unknown ring payment query key")]
    UnknownRingPaymentKey,

    #[error("duplicated ring payment query key")]
    DuplicateRingPaymentKey,

    #[error("ring payment amount is not a u64")]
    InvalidRingPaymentAmount,

    #[error("ring payment mint is not an address")]
    InvalidRingPaymentMint,

    #[error("ring payment label is not percent-encoded UTF-8")]
    InvalidRingPaymentLabel,
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
