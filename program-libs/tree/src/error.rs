use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TreeError {
    #[error("account buffer does not match the tree layout size")]
    InvalidBufferSize,
    #[error("unsupported tree height")]
    HeightTooLarge,
    #[error("tree account deserialization failed")]
    Deserialize,
    #[error("nullifier tree initialization failed")]
    NullifierInit,
    #[error("tree account is already initialized")]
    AlreadyInitialized,
    #[error("tree account has an invalid owner")]
    InvalidOwner,
    #[error("tree account is not writable")]
    NotWritable,
    #[error("invalid tree account discriminator")]
    InvalidDiscriminator,
    #[error("tree is paused")]
    Paused,
    #[error("no root at the requested index")]
    InvalidRootIndex,
    #[error("tree account data is already borrowed")]
    Borrowed,
    #[error("tree is full")]
    TreeIsFull,
    #[error("tree capacity metadata is inconsistent")]
    InvalidCapacity,
    #[error("fee arithmetic overflowed")]
    FeeOverflow,
}
