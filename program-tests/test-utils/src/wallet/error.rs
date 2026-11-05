use solana_pubkey::Pubkey;
use spr_client::ClientError;
use spr_keypair::KeypairError;
use spr_program::instruction::DepositBuildError;
use spr_transaction::{Address, TransactionError};
use thiserror::Error;

/// A failure of the test wallet's own coin selection and account resolution,
/// or of the SDK call it made.
#[derive(Debug, Error)]
pub enum WalletError {
    #[error(transparent)]
    Client(#[from] ClientError),

    #[error("insufficient balance for asset: requested {requested}, available {available}")]
    InsufficientBalance { requested: u64, available: u64 },

    #[error("unsigned input {index} is no longer available in the wallet")]
    UnsignedInputUnavailable { index: usize },

    #[error(
        "tree is required: wallet holds unspent asset {asset:?} across {tree_count} pool trees"
    )]
    AmbiguousTree { asset: Address, tree_count: usize },

    #[error("SPL token account is required for mint {mint}")]
    MissingSplTokenAccount { mint: Pubkey },

    #[error("mint {mint} is owned by unsupported SPL token program {owner}")]
    UnsupportedSplTokenProgram { mint: Pubkey, owner: Pubkey },

    #[error("split amount {amount} is not divisible into {parts} equal parts")]
    SplitNotDivisible { amount: u64, parts: u8 },

    #[error("input utxo {hash:?} is not available in the wallet")]
    InputUtxoUnavailable { hash: [u8; 32] },

    #[error(
        "input utxo {hash:?} is on tree {utxo_tree:?}, not the resolved spend tree {spend_tree:?}"
    )]
    InputUtxoTreeMismatch {
        hash: [u8; 32],
        utxo_tree: Address,
        spend_tree: Address,
    },

    #[error("split input utxo {hash:?} carries program or utxo data, which is not supported")]
    SplitInputHasData { hash: [u8; 32] },

    #[error("split input utxo {hash:?} is bound to a ring, which is not supported")]
    SplitInputRingMismatch { hash: [u8; 32] },

    #[error("account not found: {address:?}")]
    AccountNotFound { address: [u8; 32] },

    #[error("SOL deposit funding account {sender:?} must be the signing authority")]
    DepositSenderNotSigner { sender: [u8; 32] },
}

impl From<TransactionError> for WalletError {
    fn from(error: TransactionError) -> Self {
        Self::Client(error.into())
    }
}

impl From<KeypairError> for WalletError {
    fn from(error: KeypairError) -> Self {
        Self::Client(error.into())
    }
}

impl From<DepositBuildError> for WalletError {
    fn from(error: DepositBuildError) -> Self {
        Self::Client(error.into())
    }
}
