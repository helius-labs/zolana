//! Auditor side of a custom ring.
//!
//! A ring program that verifiably encrypts each transaction's viewing secret
//! key to an auditor key publishes the ciphertext as the last `messages` entry
//! of the SPP transact, tagged with the auditor key's x-coordinate. This crate
//! holds both halves of that scheme: the sender-side codec the sdk builds the
//! message with ([`encryption`]) and the auditor-side recovery that scans the
//! indexer for the tag, recovers the per-transaction viewing key, and opens the
//! confidential output slots ([`decrypt`], [`scan`]).
//!
//! It never depends on test utilities, so a service and the end-to-end tests
//! run the same code path an external auditor would.
//!
//! The recovered transaction viewing key opens Confidential-scheme output slots
//! of ring transacts. Ring deposits encrypt to the recipient and are not
//! auditor-decryptable; their amounts are public on chain.

pub mod decrypt;
pub mod encryption;
pub mod error;
pub mod scan;
pub mod types;

pub use crate::{
    decrypt::{audit_transaction, auditor_message, recover_tx_viewing_key},
    encryption::{
        auditor_view_tag, decrypt_tx_viewing_sk, derive_audit_shared_secret, encrypt_tx_viewing_sk,
        pack32_to_2fe, pack33_to_2fe, AuditEncryptionError, AuditorEncryption, AuditorMessage,
        AUDITOR_MESSAGE_LEN, AUDIT_ENC_INFO, DOM_SEP_CR_SHARED,
    },
    error::AuditError,
    scan::{audit_ring_transactions, scan_ring_transactions},
    types::{AuditedOutput, AuditedTransaction},
};
