//! Zolana wallet SDK.
//!
//! High-level, stateful wallet surface built on top of `zolana-client`: wallet
//! syncing and balances, transaction-building actions (`create_transfer`,
//! `create_withdrawal`, deposits), signing and submission, the wallet-authority
//! traits, and the on-chain user registry.
//!
//! Typical private transfer flow:
//! 1. [`sync_wallet`]
//! 2. [`create_transfer`] / [`create_withdrawal`]
//! 3. [`sign_private_transaction`] -> locally signed native `Transaction`, or
//!    [`build_private_transaction`] -> unsigned native `Transaction` for an HSM/custodian
//! 4. `rpc.send_transaction`
//! 5. `zolana_client::ZolanaClient::confirm_private_transaction(signature)` for Photon indexing
//!
//! Spend tree and recipient registry resolution are inferred internally. Use
//! [`is_wallet_registered`] / [`try_resolve_registered_address_async`] when you
//! need an explicit lookup before creating a transfer.

pub mod actions;
pub mod user_registry;
pub mod wallet_authority;
pub mod wallet_sync;

#[doc(hidden)]
pub use actions::transaction::{sign_shielded_transaction, sign_shielded_transaction_sync};
pub use actions::{
    build_deposit_transaction, build_deposit_transaction_sync, build_private_transaction,
    build_private_transaction_sync, create_associated_token_account, create_deposit, create_merge,
    create_split, create_transfer, create_transfer_sync, create_withdrawal,
    sign_private_transaction, sign_private_transaction_sync, submit_merge_transaction,
    CreatedMerge, CreatedSplit, CreatedTransfer, CreatedWithdrawal, Deposit, DepositParams,
    MergeParams, ResolvedAddress, SplitParams, SubmitMergeTransaction, SubmittedMerge,
    TransferParams, TransferRecipient, UnsignedPrivateTransaction, WithdrawalParams,
};
pub use user_registry::{
    build_registration_transaction, build_registration_transaction_sync,
    decode_user_record_account, ensure_registered, fetch_user_record_checked,
    fetch_user_record_optional_checked, fetch_user_record_optional_checked_async,
    is_wallet_registered, is_wallet_registered_sync, recipient_confidential_view_tag,
    recipient_confidential_view_tag_sync, resolve_registered_address, resolved_address_from_record,
    try_resolve_registered_address, try_resolve_registered_address_async,
    validate_registered_keypair,
};
pub use wallet_authority::{
    AnonymousRecipientSlot, ApprovalRequest, EncryptedSplit, EncryptedTransfer,
    LocalWalletAuthority, P256Signature, SyncWalletAuthority, WalletAuthority, WalletSyncMaterial,
};
pub use wallet_sync::{
    get_private_token_balances, get_private_transactions, sync_wallet, sync_wallet_async,
    sync_wallet_with_config, sync_wallet_with_config_async, SyncWalletConfig,
};
