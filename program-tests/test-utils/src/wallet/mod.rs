//! The test harness wallet: wallet state and its scan, the wallet
//! authorities, network sync over the indexer and the transaction-building
//! actions tests use to drive the programs.
//!
//! Test-only. SDK users sync by querying the indexer for their tags and
//! decrypting with `zolana_transaction::decrypt_spendable`, and build
//! transactions with `zolana_transaction` and `zolana_client` directly.

pub mod actions;
pub mod authority;
#[cfg(feature = "parallel")]
mod parallel;
mod scan;
mod state;
pub mod sync;

pub use actions::transaction::{sign_shielded_transaction, sign_shielded_transaction_sync};
pub use actions::{
    build_deposit_transaction, build_deposit_transaction_sync, build_private_transaction,
    build_private_transaction_sync, create_associated_token_account,
    create_associated_token_account_with_program, create_deposit, create_merge, create_split,
    create_transfer, create_transfer_sync, create_withdrawal, is_default_ring_spendable,
    is_plain_utxo, select_input_utxos, select_input_utxos_sync, sign_private_transaction,
    sign_private_transaction_sync, sign_private_transaction_sync_with_signers,
    sign_private_transaction_with_signers, submit_merge_transaction, CreatedMerge, CreatedSplit,
    CreatedTransfer, CreatedWithdrawal, Deposit, DepositParams, MergeParams, SelectedSpendInputs,
    SpendInputParams, SplitParams, SubmitMergeTransaction, SubmittedMerge, TransferParams,
    TransferRecipient, UnsignedPrivateTransaction, WithdrawalLeg, WithdrawalParams,
};
pub use authority::{
    AnonymousRecipientSlot, ApprovalRequest, ClientEd25519WalletAuthority, EncryptedEnvelope,
    EncryptedTransfer, KeypairWalletAuthority, SyncWalletAuthority, WalletAuthority,
    WalletSyncMaterial,
};
pub use scan::SyncConfig;
pub use state::{
    CursorStream, Filter, PrivateTransaction, PrivateTransactionDirection, PrivateTransactionId,
    PrivateTransactionKind, PrivateTransactionStatus, RingBalance, SyncReport, ViewingKeyEntry,
    Wallet, DEFAULT_TAG_WINDOW,
};
pub use sync::{
    get_private_token_balances, get_private_transactions, sync_wallet, sync_wallet_async,
    sync_wallet_with_config, sync_wallet_with_config_async, SyncWalletConfig,
};
