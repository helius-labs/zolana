use solana_program_error::ProgramError;
use spr_hasher::HasherError;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum DynamicSwapError {
    /// `settle` after the escrow's fixed deadline (`expires_at`)
    /// has passed; only `cancel` can resolve the escrow now.
    #[error("escrow has expired")]
    Expired = 9000,
    /// `cancel` before the escrow's window has passed; only `settle` can
    /// resolve the escrow yet.
    #[error("escrow has not yet expired")]
    NotYetExpired = 9001,
    #[error("proof verification failed")]
    ProofVerificationFailed = 9002,
    #[error("instruction data is invalid")]
    InvalidInstructionData = 9003,
    #[error("shielded-pool program account is invalid")]
    InvalidShieldedPoolProgram = 9004,
    /// An instruction that signs for the pair's `pool_authority` PDA
    /// (`deposit_liquidity`, `withdraw_liquidity`, `rebalance_liquidity`,
    /// `settle`) whose forwarded transact account list does not contain it.
    #[error("pool-authority account is missing from the transact account list")]
    MissingPoolAuthority = 9005,
    #[error("escrow-authority account is missing from the transact account list")]
    MissingEscrowAuthority = 9006,
    #[error("hashing failed")]
    HashingFailed = 9007,
    #[error("account address does not match the derived PDA")]
    InvalidPda = 9008,
    // 9009-9011 are retired (were NotCommitted, OutOfOrderSettlement and
    // LiquidityHashMismatch). The codes stay reserved.
    #[error("signer is not the pair's authority")]
    Unauthorized = 9012,
    // 9013 and 9014 are retired (were EscrowOutputMismatch and
    // CreatedAtOutOfTolerance). The codes stay reserved.
    #[error("account does not belong to the pair passed in")]
    PairMismatch = 9015,
    #[error("price must be nonzero")]
    InvalidPrice = 9016,
    #[error("rent recipient must be the escrow owner")]
    RentRecipientMismatch = 9017,
    // 9018 and 9019 are retired (were InvalidNullifierPubkey and
    // MaxPriceExceeded). The codes stay reserved.
    /// `create_pair` with a maker encryption pubkey that is not a
    /// tagged X25519 key with a canonical coordinate (first byte 0x04).
    #[error("maker encryption pubkey is not a canonical tagged X25519 key")]
    InvalidEncryptionPubkey = 9020,
    /// `create_pair` with a zero `expiry_slots`, which would make every escrow
    /// cancellable immediately and unsettleable.
    #[error("expiry_slots must be nonzero")]
    InvalidExpiry = 9021,
    /// `create_escrow` when `available_liquidity < max_order_size` (the worst-case
    /// reservation cannot be covered), or `withdraw_liquidity` when the
    /// withdrawn amount exceeds `available_liquidity`.
    #[error("insufficient available liquidity")]
    InsufficientLiquidity = 9022,
    /// `create_pair` with a zero `max_order_size`, which would make every
    /// escrow unprovable (owed is nonzero) and every reservation empty.
    #[error("max_order_size must be nonzero")]
    InvalidMaxOrderSize = 9023,
    // 9024 is retired (was AssetMismatch). The code stays reserved.
    #[error("deposit amount must be nonzero")]
    InvalidDepositAmount = 9025,
    /// `withdraw_liquidity` whose transact interface transfers do not consist
    /// of exactly one SplWithdrawal matching the withdrawn amount, or
    /// `deposit_liquidity` or `rebalance_liquidity` with any interface transfer
    /// present.
    #[error("transact interface transfers do not match the instruction")]
    InterfaceTransferMismatch = 9026,
    #[error("withdrawal amount must be nonzero")]
    InvalidWithdrawalAmount = 9027,
    #[error("price_tolerance must be nonzero")]
    InvalidPriceTolerance = 9028,
    #[error("min_order_amount must be nonzero")]
    InvalidMinOrderAmount = 9029,
    #[error("public price floor does not cover the current pair price")]
    PublicPriceFloorOutOfRange = 9030,
    #[error("pair price must be at least price_tolerance")]
    PriceBelowTolerance = 9031,
    /// `settle` or `skip_expired` on an order that is not at the pair's queue
    /// head. Orders resolve in FIFO order.
    #[error("order is not at the head of the pair's queue")]
    NotQueueHead = 9032,
    /// `settle` or `cancel` on an order that `cancel` already refunded; its
    /// account only marks the queue position until `skip_expired` closes it.
    #[error("escrow was already cancelled")]
    EscrowCancelled = 9033,
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
