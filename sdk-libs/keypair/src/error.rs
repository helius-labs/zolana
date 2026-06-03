use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum KeypairError {
    #[error("AEAD encryption/decryption failed")]
    Aead,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid secret key")]
    InvalidSecretKey,

    #[error("derived scalar is zero")]
    ZeroScalar,

    #[error("invalid signature-type prefix: {0}")]
    InvalidSignatureType(u8),

    #[error("HKDF expansion failed")]
    Hkdf,

    #[error("poseidon hash failed (code {0})")]
    Poseidon(u32),

    #[error("field element input exceeds 32 bytes")]
    FieldElementTooLong,

    #[error("transaction has no sender bundle")]
    EmptyTransaction,

    #[error("sender bundle too short for recipient keys: need {expected} bytes, got {actual}")]
    SenderBundleTooShort { expected: usize, actual: usize },
}
