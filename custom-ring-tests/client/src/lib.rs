//! Auditor-side client for the custom ring: scans the indexer for transactions
//! carrying the ring's auditor view tag, recovers the per-transaction viewing
//! secret key from the auditor message, and returns typed decrypted transaction
//! data.
//!
//! It never depends on test utilities: the end-to-end test asserts on the data
//! this crate returns, so it has to be the same code path an external auditor
//! would run.
//!
//! ## What goes where
//!
//! This is a fifth crate next to the four of the `sdk-tests/zk-program-swap`
//! layout (program, prover, sdk, test), and it is deliberately not part of the
//! sdk:
//!
//! - `sdk` owns the sender side (instruction builders, proof inputs, the
//!   `AuditorMessage` codec) and is what a wallet integrates.
//! - `client` (this crate) owns the auditor side: indexer scanning, key
//!   recovery, and the decrypted [`AuditedTransaction`] result type. It depends
//!   on the sdk for the message codec and adds the indexer dependency the sdk
//!   does not need.
//! - `test` drives both against localnet and asserts that what the auditor reads
//!   equals what the sender sent.
//!
//! ## Audit coverage
//!
//! The recovered transaction viewing key opens Confidential-scheme output slots
//! of ring TRANSACTs. Ring DEPOSITs encrypt to the recipient
//! (`EncryptedRingDepositData`) and are not auditor-decryptable; their amounts
//! are public on-chain anyway, so an auditor reads those from the deposit
//! instruction or event rather than by decryption.

pub mod decrypt;
pub mod error;
pub mod scan;
pub mod types;

pub use crate::{
    decrypt::{audit_transaction, auditor_message, recover_tx_viewing_key},
    error::AuditError,
    scan::{audit_ring_transactions, scan_ring_transactions},
    types::{AuditedOutput, AuditedTransaction},
};
