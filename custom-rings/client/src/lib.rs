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
//! Auditor keys open transaction slots and verified deposit disclosures.
//! Deposits without disclosure expose no opening to the auditor.

mod counters;
mod decrypt;
mod deposit;
mod deposit_encryption;
mod encryption;
mod error;
mod origin;
mod reader;
mod record;
mod recover;
mod scan;
mod types;

#[cfg(feature = "solana-rpc")]
pub use crate::origin::{ConfirmedTransaction, ORIGIN_TRANSACTION_CONFIG};
pub use crate::{
    counters::{find_counters_message, CountersSeal, SealedCounters, SpendCountersError},
    decrypt::TransactionAudit,
    deposit::{ring_deposits_in, RingDeposit},
    deposit_encryption::{DepositEncryption, DepositOpen, DepositOpening, DepositSeal},
    encryption::{
        auditor_view_tag, AuditEncryptionError, AuditorEncryption, AuditorMessage,
        NullifierKeyEnvelope, SealedNullifierKey,
    },
    error::{AuditError, RecoveryError},
    origin::{
        ring_invoked_in, ring_withdrawals_in, OriginError, RingOrigin, RingWithdrawal,
        TransactionOrigin,
    },
    reader::{
        Ed25519ReaderKey, P256ReaderKey, ReaderKey, ReaderKeyError, READ_ACCESS_RECORD_PDA_SEED,
    },
    record::{MalformedRecordCarrier, RecordCarrier},
    recover::{
        MemberRecovery, NoteDataHashes, NoteHashResolver, RecoveredNotes, RecoveryEnvironment,
        RingRecovery, SourceMember,
    },
    scan::{AuditedPage, RingAudit, RingEnvironment, RingScan, RingScanPage},
    types::{AuditedOutput, AuditedSpendRecord, AuditedTransaction},
};
pub use custom_ring_interface::AUDITOR_MESSAGE_LEN;
