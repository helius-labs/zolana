//! High-level wallet actions for shielded-pool operations over [`Rpc`].
//!
//! [`Rpc`]: zolana_client::rpc::Rpc

pub mod create_associated_token_account;
pub mod deposit;
pub mod transaction;

pub use create_associated_token_account::{
    create_associated_token_account, create_associated_token_account_with_program,
};
pub use deposit::{
    build_deposit_transaction, build_deposit_transaction_sync, create_deposit, deposit, Deposit,
    DepositParams,
};
pub use transaction::{
    build_private_transaction, build_private_transaction_sync, sign_private_transaction,
    sign_private_transaction_sync, sign_private_transaction_sync_with_signers,
    sign_private_transaction_with_signers,
};
pub use transaction::{
    create_split, create_transfer, create_transfer_sync, create_withdrawal, select_input_utxos,
    select_input_utxos_sync, CreatedSplit, CreatedTransfer, CreatedWithdrawal, SelectedSpendInputs,
    SpendInputParams, SplitParams, TransferParams, TransferRecipient, UnsignedPrivateTransaction,
    WithdrawalLeg, WithdrawalParams,
};
