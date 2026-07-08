//! Build-and-send actions for shielded-pool operations over [`Rpc`].
//!
//! [`Rpc`]: crate::rpc::Rpc

pub mod create_associated_token_account;
pub mod deposit;
pub mod spl_interface;
#[cfg(feature = "indexer-api")]
pub mod submit;
pub mod transaction;

pub use create_associated_token_account::create_associated_token_account;
pub use deposit::{create_deposit, deposit, CreateDeposit, Deposit, DEFAULT_DEPOSIT_CU_LIMIT};
pub use spl_interface::{fetch_asset_id, register_spl_interface};
#[cfg(feature = "indexer-api")]
pub use submit::{Submit, DEFAULT_TRANSACT_CU_LIMIT};
pub use transaction::{
    create_transfer, create_transfer_sync, create_withdrawal, create_withdrawal_sync,
    sign_transaction, sign_transaction_sync, CreateTransfer, CreateWithdrawal, CreatedTransfer,
    CreatedWithdrawal, ResolvedAddress, TransferRecipient,
};
