use solana_program_error::ProgramError;
use thiserror::Error;
use zolana_hasher::HasherError;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum DynamicSwapError {
    // 9000 and 9001 are retired. The codes stay pinned, do not reuse or renumber.
    #[error("escrow has expired")]
    Expired = 9000,
    #[error("escrow has not yet expired")]
    NotYetExpired = 9001,
    #[error("proof verification failed")]
    ProofVerificationFailed = 9002,
    #[error("instruction data is invalid")]
    InvalidInstructionData = 9003,
    #[error("shielded-pool program account is invalid")]
    InvalidShieldedPoolProgram = 9004,
    // 9005 is retired. The code stays pinned, do not reuse or renumber.
    #[error("pool-authority account is missing from the transact account list")]
    MissingPoolAuthority = 9005,
    #[error("escrow-authority account is missing from the transact account list")]
    MissingEscrowAuthority = 9006,
    #[error("hashing failed")]
    HashingFailed = 9007,
    #[error("account address does not match the derived PDA")]
    InvalidPda = 9008,
    // 9009 is retired. The code stays pinned, do not reuse or renumber.
    #[error("escrow has not yet been committed to a swap")]
    NotCommitted = 9009,
    // 9010 is retired. The code stays pinned, do not reuse or renumber.
    #[error("settlement is out of order with the fill queue")]
    OutOfOrderSettlement = 9010,
    // 9011 is retired. The code stays pinned, do not reuse or renumber.
    #[error("liquidity commitment hash does not match the spent pool UTXO")]
    LiquidityHashMismatch = 9011,
    #[error("signer is not the pair's authority")]
    Unauthorized = 9012,
    // 9013 is retired and stays reserved as a gap in the pinned code space.
    #[error("client-supplied created_at slot is too far from the current on-chain slot")]
    CreatedAtOutOfTolerance = 9014,
    #[error("account does not belong to the pair passed in")]
    PairMismatch = 9015,
    #[error("price must be nonzero")]
    InvalidPrice = 9016,
    #[error("rent recipient must be the escrow owner")]
    RentRecipientMismatch = 9017,
    #[error("VK registry account does not match the instruction's spec")]
    InvalidVkRegistryAccount = 9018,
    #[error("VK registry index is out of range")]
    InvalidVkRegistryIndex = 9019,
    #[error("VK registry account is already finalized")]
    VkRegistryAlreadyInitialized = 9020,
    #[error("VK registry account is not finalized")]
    VkRegistryNotReady = 9021,
    #[error("VK registry init syscall rejected the account or sources")]
    VkRegistryInitFailed = 9022,
}

impl From<DynamicSwapError> for ProgramError {
    fn from(error: DynamicSwapError) -> Self {
        ProgramError::Custom(error as u32)
    }
}

impl From<HasherError> for DynamicSwapError {
    fn from(_: HasherError) -> Self {
        Self::HashingFailed
    }
}
