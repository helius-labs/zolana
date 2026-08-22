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
//! The ring SDK owns instruction construction and proof inputs. This crate owns
//! auditor encryption, reader keys, ring-scoped indexer scans, ring
//! attribution through the Solana call stack, and decrypted audit results.
//!
//! The localnet test drives both crates and compares the audit result with the
//! transfer inputs.
//!
//! ## Audit coverage
//!
//! The recovered transaction viewing key opens confidential output slots of
//! ring transactions. Ring deposits encrypt to the recipient
//! (`EncryptedRingDepositData`) and are not auditor-decryptable; their amounts
//! are public on-chain anyway, so an auditor reads those from the deposit
//! instruction or event rather than by decryption.

mod decrypt;
mod encryption;
mod error;
mod origin;
mod reader;
mod scan;
mod types;

#[cfg(feature = "solana-rpc")]
pub use crate::origin::{ConfirmedTransaction, ORIGIN_TRANSACTION_CONFIG};
pub use crate::{
    decrypt::TransactionAudit,
    encryption::{auditor_view_tag, AuditEncryptionError, AuditorEncryption, AuditorMessage},
    error::AuditError,
    origin::{ring_invoked_in, OriginError, RingOrigin, RingWithdrawal, TransactionOrigin},
    reader::{Ed25519ReaderKey, P256ReaderKey, ReaderKey, ReaderKeyError, READER_RECORD_PDA_SEED},
    scan::{AuditedPage, RingAudit, RingEnvironment, RingScan, RingScanPage},
    types::{AuditedOutput, AuditedTransaction},
};
pub use zolana_interface::custom_ring::AUDITOR_MESSAGE_LEN;
