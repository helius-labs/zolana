use core::fmt;

use pinocchio::error::ProgramError;
use zolana_hasher::HasherError;

use crate::ExternalDataHashError;

/// A failed compressed-account check. It converts into
/// `ProgramError::Custom` with a code from [`Self::code`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompressedAccountError {
    /// The tree account is not a shielded-pool tree: another owner, another
    /// discriminator, or data that does not load as a tree.
    InvalidTreeAccount,
    /// An account's data was already borrowed.
    AccountBorrowFailed,
    /// A root index is outside the tree's root history.
    InvalidRootIndex,
    /// The nullifier PDA account is not the canonical PDA of the nullifier on
    /// the tree the roots were loaded from.
    InvalidNullifierPda,
    /// The nullifier PDA exists: the state was spent.
    StateSpent,
    /// A UTXO with a zero data hash is not program state: anyone can send one
    /// to a PDA.
    ZeroDataHash,
    /// An address seed is not a canonical BN254 scalar.
    NonCanonicalAddressSeed,
    /// A compressed account's owner is not among the PDAs the CPI signs for.
    OwnerNotSigner,
    /// A transaction writes no compressed account.
    NoAccounts,
    /// A transaction writes more compressed accounts or trees than transact
    /// can carry.
    TooManyAccounts,
    /// The inputs of one tree are not added one after another.
    InputTreesNotContiguous,
    /// Two inputs of one tree name different root indexes.
    ConflictingTreeContexts,
    /// Output data is not a compressed account's output data.
    InvalidOutputData,
    /// The external data does not match its settlement accounts or owner tags.
    InvalidExternalData,
    HashingFailed,
    SerializationFailed,
}

impl CompressedAccountError {
    /// The error's `ProgramError::Custom` code. Codes are stable.
    pub fn code(&self) -> u32 {
        match self {
            Self::InvalidTreeAccount => 14000,
            Self::AccountBorrowFailed => 14001,
            Self::InvalidRootIndex => 14002,
            Self::InvalidNullifierPda => 14003,
            Self::StateSpent => 14004,
            Self::ZeroDataHash => 14005,
            Self::NonCanonicalAddressSeed => 14006,
            Self::OwnerNotSigner => 14007,
            Self::NoAccounts => 14008,
            Self::TooManyAccounts => 14009,
            Self::InputTreesNotContiguous => 14010,
            Self::ConflictingTreeContexts => 14011,
            Self::InvalidOutputData => 14012,
            Self::InvalidExternalData => 14013,
            Self::HashingFailed => 14014,
            Self::SerializationFailed => 14015,
        }
    }
}

impl fmt::Display for CompressedAccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidTreeAccount => "tree account is not a shielded-pool tree",
            Self::AccountBorrowFailed => "account data is already borrowed",
            Self::InvalidRootIndex => "tree root index is not in the root history",
            Self::InvalidNullifierPda => "nullifier PDA does not match the state's nullifier",
            Self::StateSpent => "state is spent: its nullifier PDA exists",
            Self::ZeroDataHash => "a UTXO with a zero data hash is not program state",
            Self::NonCanonicalAddressSeed => "address seed is not a canonical BN254 scalar",
            Self::OwnerNotSigner => "a compressed account's owner is not a signing PDA",
            Self::NoAccounts => "the transaction writes no compressed account",
            Self::TooManyAccounts => "too many compressed accounts or trees for one transaction",
            Self::InputTreesNotContiguous => "the inputs of one tree are not contiguous",
            Self::ConflictingTreeContexts => "inputs of one tree name different root indexes",
            Self::InvalidOutputData => "output data is not a compressed account's",
            Self::InvalidExternalData => "external data does not match its accounts or owner tags",
            Self::HashingFailed => "hashing failed",
            Self::SerializationFailed => "serialization failed",
        };
        f.write_str(message)
    }
}

impl core::error::Error for CompressedAccountError {}

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

impl From<ExternalDataHashError> for CompressedAccountError {
    fn from(error: ExternalDataHashError) -> Self {
        match error {
            ExternalDataHashError::Serialize(_) => Self::SerializationFailed,
            ExternalDataHashError::Hasher(_) => Self::HashingFailed,
            ExternalDataHashError::SettlementAccountCount { .. }
            | ExternalDataHashError::ResolvedOwnerTagCount { .. } => Self::InvalidExternalData,
        }
    }
}
