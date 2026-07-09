//! Build-and-send actions for shielded-pool operations over [`Rpc`].
//!
//! [`Rpc`]: crate::rpc::Rpc

pub mod create_associated_token_account;
pub mod deposit;
pub mod transaction;

pub use create_associated_token_account::create_associated_token_account;
pub use deposit::{create_deposit, deposit, CreateDeposit, Deposit};
pub use transaction::{
    create_merge, create_merge_sync, create_split, create_split_sync, create_transfer,
    create_transfer_sync, create_withdrawal, create_withdrawal_sync, select_inputs,
    sign_transaction, sign_transaction_sync, CreateMerge, CreateSplit, CreateTransfer,
    CreateWithdrawal, CreatedMerge, CreatedSplit, CreatedTransfer, CreatedWithdrawal,
    InputSelection, ResolvedAddress, TransferRecipient, MAX_TRANSFER_INPUTS,
};
