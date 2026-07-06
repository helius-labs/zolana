use solana_program_error::ProgramError;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum SwapError {
    #[error("account discriminator is invalid")]
    InvalidDiscriminator = 8000,
    #[error("signer is not authorized")]
    Unauthorized = 8001,
    #[error("config account is invalid")]
    InvalidConfig = 8002,
    #[error("asset is not in the allow-list")]
    AssetNotAllowed = 8003,
    #[error("too many assets in the allow-list")]
    TooManyAssets = 8004,
    #[error("order has expired")]
    Expired = 8005,
    #[error("order has not yet expired")]
    NotYetExpired = 8006,
    #[error("proof verification failed")]
    ProofVerificationFailed = 8007,
    #[error("taker signature is invalid")]
    InvalidTakerSignature = 8008,
    #[error("payout does not match order terms")]
    PayoutMismatch = 8009,
    #[error("derived program address does not match")]
    InvalidPda = 8010,
    #[error("instruction data is invalid")]
    InvalidInstructionData = 8011,
    #[error("escrow address derivation failed")]
    AddressDerivation = 8012,
    #[error("escrow-authority account is missing from the transact account list")]
    MissingEscrowAuthority = 8013,
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
            (InvalidDiscriminator as u32, 8000),
            (Unauthorized as u32, 8001),
            (InvalidConfig as u32, 8002),
            (AssetNotAllowed as u32, 8003),
            (TooManyAssets as u32, 8004),
            (Expired as u32, 8005),
            (NotYetExpired as u32, 8006),
            (ProofVerificationFailed as u32, 8007),
            (InvalidTakerSignature as u32, 8008),
            (PayoutMismatch as u32, 8009),
            (InvalidPda as u32, 8010),
            (InvalidInstructionData as u32, 8011),
            (AddressDerivation as u32, 8012),
            (MissingEscrowAuthority as u32, 8013),
        ];
        for (got, want) in table {
            assert_eq!(got, want, "error code drifted");
        }
    }
}
