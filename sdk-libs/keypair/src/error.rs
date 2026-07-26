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

    #[error("field element input exceeds 32 bytes")]
    FieldElementTooLong,

    #[error("p256 prehash must be 32 bytes, got {0}")]
    InvalidPrehashLength(usize),

    /// `pack_info` packs the key-schedule `info` into two field elements, so an
    /// `info` longer than 62 bytes has nowhere to go. Refusing it keeps a caller
    /// supplied label from indexing past the second limb.
    #[error("key-schedule info exceeds 62 bytes")]
    InfoTooLong,
}
