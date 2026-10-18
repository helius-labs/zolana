//! The custom ring's auditor client. It never depends on test utilities, so the end-to-end
//! test asserts on the code path an auditor runs.

mod decrypt;
mod deposit;
mod encryption;
mod error;
mod merge_audit;
mod opening;
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
    decrypt::{recover_tx_viewing_key, TransactionAudit},
    deposit::{deposit_payload, ring_deposits_in, RingDeposit},
    encryption::{
        auditor_view_tag, open_deposit, seal_deposits, AnonymousDisclosure, AnonymousOutputOpening,
        AuditInputOpening, AuditorEncryption, AuditorMessage, DepositEncryption, DepositOpening,
        NullifierKeyEnvelope, SealedNullifierKey,
    },
    error::AuditError,
    merge_audit::{AuditedMerge, MergeAudit, MergeAuditPage, MergeAuditResult, UnresolvedMerge},
    origin::{
        ring_event_origin_in, ConfirmedDeposit, ConfirmedEvent, ConfirmedEventKind, RingOrigin,
        RingWithdrawal, TransactionOrigin,
    },
    reader::{
        Ed25519ReaderKey, P256ReaderKey, ReaderKey, ReaderKeyError, READ_ACCESS_RECORD_PDA_SEED,
    },
    recover::{MemberRecovery, RecoveredNotes, RingRecovery, SourceMember},
    scan::{AuditedPage, RingScan, RingScanPage, ScanPage},
    types::{AuditedOutput, AuditedTransaction},
};
pub use custom_ring_interface::AUDITOR_MESSAGE_LEN;
