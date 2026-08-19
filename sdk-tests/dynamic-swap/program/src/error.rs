use solana_program_error::ProgramError;
use thiserror::Error;
use zolana_hasher::HasherError;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum DynamicSwapError {
    /// `settle` after the escrow's window (`created_at + pair.expiry_slots`)
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
    /// A pool-spending instruction (`withdraw_liquidity`,
    /// `rebalance_liquidity`, `settle`) whose forwarded transact account list
    /// does not contain the pair's `pool_authority` PDA, so the CPI could not
    /// sign for the pool notes.
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
    // each escrow is self-contained, so there is no shared pool to order
    // settlements against. Kept as a pinned, stable code.
    #[error("settlement is out of order with the fill queue")]
    OutOfOrderSettlement = 9010,
    // 9011 retired (was LiquidityHashMismatch): there is no shared pool, so no
    // `Liquidity.available_hash` binding remains. Kept as a pinned, stable code.
    #[error("liquidity commitment hash does not match the spent pool UTXO")]
    LiquidityHashMismatch = 9011,
    #[error("signer is not the pair's authority")]
    Unauthorized = 9012,
    // 9013 is retired (was EscrowOutputMismatch): the order output hash is read
    // directly from the transact outputs, so no client claim can diverge. The
    // code is left as an unused gap rather than renumbering the stable codes
    // around it.
    // 9014 retired (was CreatedAtOutOfTolerance): created_at is program-stamped
    // from the Clock sysvar, so there is no client-supplied slot to bound. Kept
    // as a pinned, stable code.
    #[error("client-supplied created_at slot is too far from the current on-chain slot")]
    CreatedAtOutOfTolerance = 9014,
    #[error("account does not belong to the pair passed in")]
    PairMismatch = 9015,
    #[error("price must be nonzero")]
    InvalidPrice = 9016,
    #[error("rent recipient must be the escrow owner")]
    RentRecipientMismatch = 9017,
    // 9018 retired (was InvalidNullifierPubkey): the escrow-authority nullifier
    // pubkey is no longer maker-supplied -- it is the hardcoded zero-secret
    // constant `ESCROW_NULLIFIER_PUBKEY`. Kept as a pinned, stable code.
    #[error("escrow-authority nullifier pubkey must be nonzero")]
    InvalidNullifierPubkey = 9018,
    /// `create_escrow` when the pair's current price exceeds the taker's
    /// `max_price` -- protection against an `update_price` landing between the
    /// taker building the transaction and the escrow's creation.
    #[error("pair price exceeds the taker's max_price")]
    MaxPriceExceeded = 9019,
    /// `create_pair` with a maker encryption pubkey that is not a
    /// SEC1-compressed P256 point (first byte 0x02/0x03).
    #[error("maker encryption pubkey is not a compressed P256 point")]
    InvalidEncryptionPubkey = 9020,
    /// `create_pair` with a zero `expiry_slots`, which would make every escrow
    /// cancellable immediately and unsettleable.
    #[error("expiry_slots must be nonzero")]
    InvalidExpiry = 9021,
    /// `create_escrow` when `liquidity_bound < max_order_size` (the worst-case
    /// reservation cannot be covered), or `withdraw_liquidity` when the
    /// withdrawn amount exceeds `liquidity_bound`.
    #[error("insufficient committed liquidity")]
    InsufficientLiquidity = 9022,
    /// `create_pair` with a zero `max_order_size`, which would make every
    /// escrow unprovable (owed is nonzero) and every reservation empty.
    #[error("max_order_size must be nonzero")]
    InvalidMaxOrderSize = 9023,
    /// `deposit_liquidity` whose mint does not hash to the pair's destination
    /// asset commitment.
    #[error("deposit mint does not match the pair's destination asset")]
    AssetMismatch = 9024,
    /// `deposit_liquidity` whose forwarded deposit data violates the pool-note
    /// shape: not exactly one SPL asset and one entry, a zero amount, an owner
    /// that is not the pair's pool_authority owner-hash, or utxo data that does
    /// not commit `booked = amount`.
    #[error("deposit entry does not form a valid pool note")]
    InvalidDepositEntry = 9025,
    /// `withdraw_liquidity` whose transact interface transfers do not consist
    /// of exactly one SplWithdrawal matching the withdrawn amount (or any
    /// transfer at all for `amount = 0`), or `rebalance_liquidity` with any
    /// interface transfer present.
    #[error("transact interface transfers do not match the instruction")]
    InterfaceTransferMismatch = 9026,
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
