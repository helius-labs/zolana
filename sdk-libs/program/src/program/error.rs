use pinocchio::error::ProgramError;
use thiserror::Error;
use zolana_hasher::HasherError;

/// A failed compressed-account check. It converts into
/// `ProgramError::Custom` with a code from [`Self::code`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[repr(u32)]
pub enum CompressedAccountError {
    /// The tree account is not a shielded-pool tree: another owner, another
    /// discriminator, or data that does not load as a tree.
    #[error("tree account is not a shielded-pool tree")]
    InvalidTreeAccount = 14000,
    /// An account's data was already borrowed.
    #[error("account data is already borrowed")]
    AccountBorrowFailed = 14001,
    /// A root index is outside the tree's root history.
    #[error("tree root index is not in the root history")]
    InvalidRootIndex = 14002,
    /// The nullifier PDA account is not the canonical PDA of the nullifier on
    /// the tree the roots were loaded from.
    #[error("nullifier PDA does not match the state's nullifier")]
    InvalidNullifierPda = 14003,
    /// The nullifier PDA exists: the state was spent.
    #[error("state is spent: its nullifier PDA exists")]
    StateSpent = 14004,
    /// A UTXO with a zero data hash is not program state: anyone can send one
    /// to a PDA.
    #[error("a UTXO with a zero data hash is not program state")]
    ZeroDataHash = 14005,
    /// An address seed is not a canonical BN254 scalar.
    #[error("address seed is not a canonical BN254 scalar")]
    NonCanonicalAddressSeed = 14006,
    /// A compressed account's owner is not among the PDAs the CPI signs for.
    #[error("a compressed account's owner is not a signing PDA")]
    OwnerNotSigner = 14007,
    /// A transaction writes no compressed account.
    #[error("the transaction writes no compressed account")]
    NoAccounts = 14008,
    /// A transaction writes more compressed accounts or trees than transact
    /// can carry, or a number of accounts with no supported square shape.
    #[error("too many compressed accounts or trees for one transaction")]
    TooManyAccounts = 14009,
    /// Two inputs of one tree name different root indexes.
    #[error("inputs of one tree name different root indexes")]
    ConflictingTreeContexts = 14011,
    #[error("hashing failed")]
    HashingFailed = 14013,
    #[error("serialization failed")]
    SerializationFailed = 14014,
}

impl CompressedAccountError {
    pub const fn code(self) -> u32 {
        self as u32
    }
}

impl From<CompressedAccountError> for ProgramError {
    fn from(error: CompressedAccountError) -> Self {
        ProgramError::Custom(error.code())
    }
}

impl From<HasherError> for CompressedAccountError {
    fn from(_: HasherError) -> Self {
        Self::HashingFailed
    }
}
