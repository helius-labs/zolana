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

    #[error("HKDF expansion failed")]
    Hkdf,

    #[error("SLIP-0010 derivation failed")]
    Slip10Derivation,

    #[error("derivation account index {0} exceeds the hardened-index range")]
    InvalidDerivationAccount(u32),

    #[error("poseidon hash failed (code {0})")]
    Poseidon(u32),

    #[error("field element input exceeds 32 bytes")]
    FieldElementTooLong,
}
