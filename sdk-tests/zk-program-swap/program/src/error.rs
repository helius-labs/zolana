use solana_program_error::ProgramError;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum SwapError {
    #[error("order has expired")]
    Expired = 8005,
    #[error("order has not yet expired")]
    NotYetExpired = 8006,
    #[error("proof verification failed")]
    ProofVerificationFailed = 8007,
    #[error("derived program address does not match")]
    InvalidPda = 8010,
    #[error("instruction data is invalid")]
    InvalidInstructionData = 8011,
    #[error("escrow-authority account is missing from the transact account list")]
    MissingEscrowAuthority = 8013,
    #[error("create-swap transact must carry exactly one marker message")]
    InvalidMarkerMessage = 8014,
    #[error("create-swap marker message data must be empty")]
    MarkerDataNotEmpty = 8015,
}

impl From<SwapError> for ProgramError {
    fn from(error: SwapError) -> Self {
        ProgramError::Custom(error as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::SwapError::*;

    #[test]
    fn error_codes_are_stable() {
        let table = [
            (Expired as u32, 8005),
            (NotYetExpired as u32, 8006),
            (ProofVerificationFailed as u32, 8007),
            (InvalidPda as u32, 8010),
            (InvalidInstructionData as u32, 8011),
            (MissingEscrowAuthority as u32, 8013),
            (InvalidMarkerMessage as u32, 8014),
            (MarkerDataNotEmpty as u32, 8015),
        ];
        for (got, want) in table {
            assert_eq!(got, want, "error code drifted");
        }
    }
}
