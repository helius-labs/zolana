use std::{collections::BTreeSet, time::Instant};

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::VersionedMessage;
use solana_signature::Signature;
use zolana_client::{compile_message, ComputeBudgetConfig, DEFAULT_TRANSACT_CU_LIMIT};
use zolana_interface::{
    instruction::{tag, TransactIxData},
    PROGRAM_ID_PUBKEY,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::WalletUtxo;

use crate::kvault::{VaultAccounts, VaultState};

const FULL_BPS: u64 = 10_000;
pub const MAKER_CACHE_SLOT: u8 = 0;
pub const SWAP_COMPUTE_BUDGET: ComputeBudgetConfig =
    ComputeBudgetConfig::new(2 * DEFAULT_TRANSACT_CU_LIMIT);

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
    #[error("the user has no {asset} utxo covering {required}")]
    InsufficientFunds { asset: Address, required: u64 },
    #[error("the swap carries {count} interface transfers")]
    PublicTransfer { count: usize },
    #[error("the transaction is not the user's leg followed by one maker transact")]
    UnexpectedTransaction,
    #[error("the transaction does not carry the user's leg as the user built it")]
    UserLegAltered,
    #[error("the maker's leg pays the user {received} outputs, expected one")]
    UnexpectedOutputs { received: usize },
    #[error("output {slot} does not open to its commitment")]
    CommitmentMismatch { slot: usize },
    #[error("the user's leg pays the maker {received}, the quote takes {expected}")]
    Underpaid { expected: u64, received: u64 },
    #[error("the fill pays {offered}, the vault rate minus the fee pays {expected}")]
    BelowRate { expected: u64, offered: u64 },
    #[error("the user's leg takes {inputs} inputs, the quote allows {max}")]
    UserLegTooWide { inputs: usize, max: usize },
    #[error("the user's leg has {outputs} outputs, the quote expects {expected}")]
    UserLegOutputs { outputs: usize, expected: usize },
    #[error("the user's balance needs {needed} inputs, the quote allows {max}")]
    TooManyInputs { needed: usize, max: usize },
    #[error("no supported shape takes {inputs} inputs and {outputs} outputs")]
    NoSupportedShape { inputs: usize, outputs: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Deposit,
    Exit,
}

impl Direction {
    pub fn assets(self, vault: &VaultAccounts) -> (Address, Address) {
        match self {
            Self::Deposit => (vault.token_mint, vault.shares_mint),
            Self::Exit => (vault.shares_mint, vault.token_mint),
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
        let gross = match direction {
            Direction::Deposit => rate.deposit(amount_in)?.shares,
            Direction::Exit => rate.withdraw(amount_in)?.tokens,
        };
        let amount_out = u64::try_from(
            u128::from(gross) * u128::from(FULL_BPS.saturating_sub(fee_bps)) / u128::from(FULL_BPS),
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
    pub quote: Quote,
    pub maker: ShieldedAddress,
    pub fee_payer: Address,
    pub max_user_inputs: usize,
    pub user_outputs: usize,
}

pub struct SwapRequest {
    pub quote: Quote,
    pub user: ShieldedAddress,
    pub leg: Instruction,
}

pub struct Order {
    pub offer: Offer,
    pub inputs: Vec<WalletUtxo>,
    pub request: SwapRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spend {
    pub nullifier: [u8; 32],
    pub cache_slot: Option<u8>,
}

pub struct Fill {
    pub step: u64,
    pub message: VersionedMessage,
    pub spent: Vec<Spend>,
    pub change: Vec<WalletUtxo>,
    pub expires_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Holdings {
    pub usdc: u64,
    pub shares: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultOperation {
    pub before: VaultState,
    pub after: VaultState,
    pub tokens: u64,
    pub shares: u64,
    pub inputs: usize,
    pub signature: Signature,
}

pub fn swap_message(
    fee_payer: &Address,
    legs: [Instruction; 2],
    blockhash: Hash,
) -> Result<VersionedMessage> {
    Ok(compile_message(
        fee_payer,
        &legs,
        blockhash,
        SWAP_COMPUTE_BUDGET,
    )?)
}

pub fn instructions(message: &VersionedMessage) -> Result<Vec<Instruction>> {
    let keys = message.static_account_keys();
    let key = |index: u8| -> Result<Address> {
        Ok(*keys
            .get(usize::from(index))
            .ok_or(SwapError::UnexpectedTransaction)?)
    };
    message
        .instructions()
        .iter()
        .map(|compiled| {
            let accounts = compiled
                .accounts
                .iter()
                .map(|&index| {
                    Ok(AccountMeta {
                        pubkey: key(index)?,
                        is_signer: message.is_signer(usize::from(index)),
                        is_writable: message.is_maybe_writable_with_reserved_addresses(
                            usize::from(index),
                            None::<&BTreeSet<Address>>,
                        ),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Instruction {
                program_id: key(compiled.program_id_index)?,
                accounts,
                data: compiled.data.clone(),
            })
        })
        .collect()
}

pub fn transact_data(instruction: &Instruction) -> Result<TransactIxData> {
    if instruction.program_id != PROGRAM_ID_PUBKEY {
        return Err(SwapError::UnexpectedTransaction.into());
    }
    let Some((&tag::TRANSACT, payload)) = instruction.data.split_first() else {
        return Err(SwapError::UnexpectedTransaction.into());
    };
    TransactIxData::deserialize(payload).map_err(|e| anyhow!("decode transact: {e}"))
}

pub fn legs(message: &VersionedMessage) -> Result<Vec<TransactIxData>> {
    instructions(message)?.iter().map(transact_data).collect()
}
