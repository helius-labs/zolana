use thiserror::Error;

#[derive(Debug, Clone, Copy, Error, PartialEq)]
pub enum AccountError {
    #[error("Account owned by wrong program.")]
    AccountOwnedByWrongProgram,
    #[error("Account not mutable.")]
    AccountNotMutable,
    #[error("Invalid Discriminator.")]
    InvalidDiscriminator,
    #[error("Borrow account data failed.")]
    BorrowAccountDataFailed,
    #[error("Account is already initialized.")]
    AlreadyInitialized,
    #[error("Invalid Account size.")]
    InvalidAccountSize,
    #[error("Account is mutable.")]
    AccountMutable,
    #[error("Invalid account balance.")]
    InvalidAccountBalance,
    #[error("Invalid Signer")]
    InvalidSigner,
    #[error("Invalid Program Id")]
    InvalidProgramId,
    #[error("Program not executable.")]
    ProgramNotExecutable,
    #[error("Account not zeroed.")]
    AccountNotZeroed,
    #[error("Not enough account keys provided.")]
    NotEnoughAccountKeys,
    #[error("Invalid Account.")]
    InvalidAccount,
}

impl From<AccountError> for u32 {
    fn from(e: AccountError) -> u32 {
        match e {
            AccountError::InvalidDiscriminator => 20000,
            AccountError::AccountOwnedByWrongProgram => 20001,
            AccountError::AccountNotMutable => 20002,
            AccountError::BorrowAccountDataFailed => 20003,
            AccountError::InvalidAccountSize => 20004,
            AccountError::AccountMutable => 20005,
            AccountError::AlreadyInitialized => 20006,
            AccountError::InvalidAccountBalance => 20007,
            AccountError::InvalidSigner => 20009,
            AccountError::InvalidProgramId => 20011,
            AccountError::ProgramNotExecutable => 20012,
            AccountError::AccountNotZeroed => 20013,
            AccountError::NotEnoughAccountKeys => 20014,
            AccountError::InvalidAccount => 20015,
        }
    }
}

impl From<AccountError> for solana_program_error::ProgramError {
    fn from(e: AccountError) -> Self {
        solana_program_error::ProgramError::Custom(e.into())
    }
}
