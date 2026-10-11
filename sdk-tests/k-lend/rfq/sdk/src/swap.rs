use std::time::Instant;

use anyhow::Result;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_message::VersionedMessage;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::WalletUtxo;

use crate::pair::{Pair, VaultState};

const FULL_BPS: u64 = 10_000;

pub fn validate_fee(fee_bps: u64) -> Result<(), SwapError> {
    if fee_bps >= FULL_BPS {
        return Err(SwapError::InvalidFee { fee_bps });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SwapError {
    #[error(
        "the market maker's largest {asset} utxo holds {available}, the fill needs {required}"
    )]
    InsufficientInventory {
        asset: Address,
        required: u64,
        available: u64,
    },
    #[error(
        "the market maker cannot pay {required} {asset} with at most {max_inputs} inputs next to a user transfer"
    )]
    MakerTransferTooWide {
        asset: Address,
        required: u64,
        max_inputs: usize,
    },
    #[error(
        "the swap would leave {asset} at {balance_after}, outside its target range {min}..={max}"
    )]
    OutsideTargetRange {
        asset: Address,
        balance_after: u64,
        min: u64,
        max: u64,
    },
    #[error("the user has no {asset} utxo covering {required}")]
    InsufficientFunds { asset: Address, required: u64 },
    #[error("the swap carries {count} interface transfers")]
    PublicTransfer { count: usize },
    #[error("the transaction is not the user's transfer followed by one maker transact")]
    UnexpectedTransaction,
    #[error("the accepted offer belongs to a different swap pair")]
    WrongPair,
    #[error("the transaction does not carry the user's transfer as the user built it")]
    UserTransferAltered,
    #[error("the maker's transfer pays the user {received} outputs, expected one")]
    UnexpectedOutputs { received: usize },
    #[error("output {slot} does not open to its commitment")]
    CommitmentMismatch { slot: usize },
    #[error("the user's transfer pays the maker {received}, the quote takes {expected}")]
    Underpaid { expected: u64, received: u64 },
    #[error("the request asks for {requested}, the maker's current quote pays {expected}")]
    QuoteMismatch { expected: u64, requested: u64 },
    #[error("the fill pays {offered}, the accepted quote promises {expected}")]
    BelowQuote { expected: u64, offered: u64 },
    #[error("swap fee {fee_bps} bps must be below 10000")]
    InvalidFee { fee_bps: u64 },
    #[error("the swap amount must be positive")]
    AmountZero,
    #[error("the user transfer must authorize only the user's input owner {expected}")]
    UserTransferSigner { expected: Address },
    #[error("user input {nullifier:?} is already spent")]
    UserInputSpent { nullifier: [u8; 32] },
    #[error("user input {nullifier:?} already belongs to an in-flight fill")]
    DuplicateFill { nullifier: [u8; 32] },
    #[error("the user's transfer takes {inputs} inputs, the quote allows {max}")]
    UserTransferTooWide { inputs: usize, max: usize },
    #[error("the user's transfer has {outputs} outputs, the quote expects {expected}")]
    UserTransferOutputs { outputs: usize, expected: usize },
    #[error("the user's transfer pays the maker {received} notes, expected one")]
    UserPaymentOutputs { received: usize },
    #[error("the user's balance needs {needed} inputs, the quote allows {max}")]
    TooManyInputs { needed: usize, max: usize },
    #[error("no supported shape takes {inputs} inputs and {outputs} outputs")]
    NoSupportedShape { inputs: usize, outputs: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Deposit,
    Withdrawal,
}

impl Direction {
    pub fn assets(self, pair: &Pair) -> (Address, Address) {
        match self {
            Self::Deposit => (pair.token_mint, pair.shares_mint),
            Self::Withdrawal => (pair.shares_mint, pair.token_mint),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quote {
    pub direction: Direction,
    pub amount_in: u64,
    pub amount_out: u64,
}

impl Quote {
    pub fn price(
        rate: &VaultState,
        direction: Direction,
        amount_in: u64,
        fee_bps: u64,
    ) -> Result<Self> {
        validate_fee(fee_bps)?;
        if amount_in == 0 {
            return Err(SwapError::AmountZero.into());
        }
        let gross = match direction {
            Direction::Deposit => rate.deposit(amount_in)?.shares,
            Direction::Withdrawal => rate.withdraw(amount_in)?.tokens,
        };
        let amount_out = u64::try_from(
            u128::from(gross) * u128::from(FULL_BPS - fee_bps) / u128::from(FULL_BPS),
        )?;
        Ok(Self {
            direction,
            amount_in,
            amount_out,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offer {
    pub pair: Pair,
    pub quote: Quote,
    pub fee_bps: u64,
    pub maker: ShieldedAddress,
    pub fee_payer: Address,
    pub max_user_inputs: usize,
    pub user_outputs: usize,
}

impl Offer {
    /// Check pricing against an independently read vault state before accepting the offer.
    pub fn verify_price(&self, rate: &VaultState) -> Result<()> {
        let expected = Quote::price(
            rate,
            self.quote.direction,
            self.quote.amount_in,
            self.fee_bps,
        )?;
        if expected != self.quote {
            return Err(SwapError::QuoteMismatch {
                expected: expected.amount_out,
                requested: self.quote.amount_out,
            }
            .into());
        }
        Ok(())
    }
}

pub struct SwapRequest {
    pub quote: Quote,
    pub user: ShieldedAddress,
    pub transfer: Instruction,
}

pub struct Order {
    pub offer: Offer,
    pub inputs: Vec<WalletUtxo>,
    pub request: SwapRequest,
}

pub struct Fill {
    pub message: VersionedMessage,
    pub expires_at: Instant,
}

#[cfg(test)]
mod tests;
