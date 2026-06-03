use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    #[error("AEAD encryption/decryption failed")]
    Aead,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid secret key")]
    InvalidSecretKey,

    #[error("invalid signature-type prefix: {0}")]
    InvalidSignatureType(u8),

    #[error("HKDF expansion failed")]
    Hkdf,

    #[error("poseidon hash failed")]
    Poseidon,
}
