//! The custom ring's auditor client. It never depends on test utilities, so the end-to-end
//! test asserts on the code path an auditor runs.

mod counters;
mod decrypt;
mod deposit;
mod encryption;
mod error;
mod origin;
mod reader;
mod recover;
#[cfg(feature = "rpc")]
pub mod rpc;
mod scan;
mod types;

#[cfg(feature = "solana-rpc")]
pub use crate::origin::{confirmed_origin, ORIGIN_TRANSACTION_CONFIG};
pub use crate::{
    counters::{find_counters_message, open_counters, seal_counters},
    decrypt::{recover_tx_viewing_key, TransactionAudit},
    deposit::{deposit_payload, ring_deposits_in, RingDeposit},
    encryption::{
        auditor_view_tag, open_deposit, seal_deposits, AuditorEncryption, AuditorMessage,
        DepositEncryption, DepositOpening, NullifierKeyEnvelope, SealedNullifierKey,
    },
    error::AuditError,
    origin::{ring_event_origin_in, RingOrigin, RingWithdrawal, TransactionOrigin},
    reader::{
        Ed25519ReaderKey, P256ReaderKey, ReaderKey, ReaderKeyError, READ_ACCESS_RECORD_PDA_SEED,
    },
    recover::{
        MemberRecovery, NoteDataHashes, NoteHashResolver, RecoveredNotes, RingRecovery,
        SourceMember,
    },
    scan::{AuditedPage, RingScan, RingScanPage, ScanPage},
    types::{AuditedOutput, AuditedSpendRecord, AuditedTransaction},
};
pub use custom_ring_interface::AUDITOR_MESSAGE_LEN;
