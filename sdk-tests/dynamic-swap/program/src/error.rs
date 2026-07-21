use solana_program_error::ProgramError;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum DynamicSwapError {
    // 9000/9001 retired (were Expired/NotYetExpired): pricing is folded into
    // create_escrow, so there is no uncommitted/timeout-expire path left to
    // gate. Kept as pinned, stable codes rather than renumbering the space.
    #[error("escrow has expired")]
    Expired = 9000,
    #[error("escrow has not yet expired")]
    NotYetExpired = 9001,
    #[error("proof verification failed")]
    ProofVerificationFailed = 9002,
    #[error("instruction data is invalid")]
    InvalidInstructionData = 9003,
    #[error("trailing account is not the shielded-pool program")]
    InvalidShieldedPoolProgram = 9004,
    // 9005 retired (was MissingPoolAuthority): there is no pool_authority PDA any
    // more; the multi-PDA CPI's non-escrow-authority branch is now unreachable.
    // Kept as a pinned, stable code.
    #[error("pool-authority account is missing from the transact account list")]
    MissingPoolAuthority = 9005,
    #[error("escrow-authority account is missing from the transact account list")]
    MissingEscrowAuthority = 9006,
    #[error("hashing failed")]
    HashingFailed = 9007,
    #[error("account address does not match the derived PDA")]
    InvalidPda = 9008,
    // 9009 retired (was NotCommitted): every escrow is priced at creation, so an
    // uncommitted escrow can no longer exist. Kept as a pinned, stable code.
    #[error("escrow has not yet been committed to a swap")]
    NotCommitted = 9009,
    // 9010 retired (was OutOfOrderSettlement): the strict fill queue is removed --
    // each escrow is self-contained (its own locked order + reservation UTXOs), so
    // there is no shared pool to order settlements against. Kept as a pinned,
    // stable code.
    #[error("settlement is out of order with the fill queue")]
    OutOfOrderSettlement = 9010,
    // 9011 retired (was LiquidityHashMismatch): there is no shared pool, so no
    // `Liquidity.available_hash` binding remains. Kept as a pinned, stable code.
    #[error("liquidity commitment hash does not match the spent pool UTXO")]
    LiquidityHashMismatch = 9011,
    #[error("signer is not the pair's authority")]
    Unauthorized = 9012,
    // 9013 is retired (was EscrowOutputMismatch): escrow/reservation output
    // hashes are read directly from the transact outputs, so no client claim can
    // diverge. The code is left as an unused gap rather than renumbering the
    // stable codes around it.
    #[error("client-supplied created_at slot is too far from the current on-chain slot")]
    CreatedAtOutOfTolerance = 9014,
    #[error("account does not belong to the pair passed in")]
    PairMismatch = 9015,
    #[error("price must be nonzero")]
    InvalidPrice = 9016,
    #[error("rent recipient must be the escrow owner")]
    RentRecipientMismatch = 9017,
}

impl From<DynamicSwapError> for ProgramError {
    fn from(error: DynamicSwapError) -> Self {
        ProgramError::Custom(error as u32)
    }
}
