use pinocchio::error::ProgramError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum CompressionError {
    InvalidInstructionData = 1,
    InvalidAccounts = 2,
    InvalidAuthority = 3,
    InvalidPda = 4,
    InvalidTree = 5,
    InvalidTransact = 6,
    InvalidAddress = 7,
    InvalidState = 8,
    HashingFailed = 9,
    SerializationFailed = 10,
}

impl From<CompressionError> for ProgramError {
    fn from(error: CompressionError) -> Self {
        Self::Custom(error as u32)
    }
}
