//! High-level wallet actions for shielded-pool operations over [`Rpc`].
//!
//! [`Rpc`]: crate::rpc::Rpc

pub mod create_associated_token_account;
pub mod deposit;
pub mod transaction;

pub use create_associated_token_account::create_associated_token_account;
pub use deposit::{create_deposit, deposit, Deposit, DepositParams};
#[cfg(feature = "indexer-api")]
pub(crate) use transaction::SignedPrivateTransaction;
pub use transaction::{
    create_transfer, create_transfer_sync, create_withdrawal, CreatedTransfer, CreatedWithdrawal,
    ResolvedAddress, TransferParams, TransferRecipient, UnsignedPrivateTransaction,
    WithdrawalParams,
};
#[cfg(feature = "indexer-api")]
pub use transaction::{sign_private_transaction, sign_private_transaction_sync};
