//! Build-and-send actions for shielded-pool operations over [`Rpc`].
//!
//! [`Rpc`]: crate::rpc::Rpc

pub mod create_associated_token_account;
pub mod deposit;
pub mod submit;
pub mod transaction;

pub use create_associated_token_account::create_associated_token_account;
pub use deposit::{create_deposit, deposit, CreateDeposit, Deposit};
pub use submit::{submit_private_transaction, SubmitPrivateTransaction};
pub use transaction::{
    create_split, create_split_sync, create_transfer, create_transfer_sync, create_withdrawal,
    create_withdrawal_sync, sign_transaction, sign_transaction_sync, CreateSplit, CreateTransfer,
    CreateWithdrawal, CreatedSplit, CreatedTransfer, CreatedWithdrawal, InputSelection,
    MAX_TRANSFER_INPUTS,
};
