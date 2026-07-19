use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
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

    #[error("HKDF expansion failed")]
    Hkdf,

    #[error("poseidon hash failed (code {0})")]
    Poseidon(u32),

    #[error("info string exceeds 62 bytes")]
    InfoTooLong,
}
