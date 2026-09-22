//! The wallet authority surface: the key-holding capability every wallet
//! operation is signed and encrypted through.
//!
//! `P256Signature` is defined in `zolana-transaction` because the prover
//! consumes it below this crate; it is re-exported here because
//! [`SyncWalletAuthority::sign_p256`] returns it.

pub use crate::wallet::authority::{
    AnonymousRecipientSlot, ApprovalRequest, ClientEd25519WalletAuthority, EncryptedEnvelope,
    EncryptedTransfer, KeypairWalletAuthority, SyncWalletAuthority, WalletAuthority,
    WalletSyncMaterial,
};
pub use zolana_transaction::P256Signature;
