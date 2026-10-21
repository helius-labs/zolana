//! The custom ring's auditor client, the end-to-end test asserts on the path an auditor runs.

mod created;
mod decrypt;
mod deposit;
mod disclosure;
mod encryption;
mod error;
mod merge_audit;
mod origin;
mod reader;
pub mod records;
mod recover;
#[cfg(feature = "rpc")]
pub mod rpc;
mod scan;
mod types;

#[cfg(feature = "solana-rpc")]
pub use crate::origin::{confirmed_origin, ORIGIN_TRANSACTION_CONFIG};
pub use crate::{
    created::{CreatedNote, CreatedNotePage, CreatedNoteScan, CreatedNotes},
    decrypt::{EscrowedKeys, KnownNotes, TransactionAudit},
    deposit::{ring_deposits_in, RingDeposit},
    disclosure::{
        AnonymousDisclosure, AnonymousInputOpening, AnonymousInputs, AnonymousOutputOpening,
        AuditDisclosure, AuditEnvelope, DeliveredOutputOpening, DisclosurePad, PackedOutputOpening,
        PublishedOutputs, SealedAuditEnvelope,
    },
    encryption::{
        auditor_view_tag, open_deposit, open_merge_disclosure, seal_deposits, DepositEncryption,
        DepositOpening, MergeDisclosureEncryption, MergeOpening, NullifierKeyEnvelope,
        SealedNullifierKey,
    },
    error::AuditError,
    merge_audit::{
        AuditedMerge, MergeAudit, MergeAuditPage, MergeAuditResult, MergeKeys, UnresolvedMerge,
    },
    origin::{
        ring_event_origin_in, ConfirmedDeposit, ConfirmedEvent, ConfirmedEventKind,
        ConfirmedMergeDisclosure, RingOrigin, RingWithdrawal, TransactionOrigin,
    },
    reader::{
        Ed25519ReaderKey, P256ReaderKey, ReaderKey, ReaderKeyError, READ_ACCESS_RECORD_PDA_SEED,
    },
    records::{
        apply_proof_inputs, complete_member_page, member_record, quad_path, MemberOpeningRead,
        RegistryTip,
    },
    recover::{MemberRecovery, RecoveredNotes, RingRecovery, SourceMember},
    scan::{AuditedPage, RingScan, RingScanPage, ScanPage},
    types::{
        AuditedInput, AuditedInputOpening, AuditedNote, AuditedOutput, AuditedSender,
        AuditedTransaction, InputRing, KnownNote, OutputOpening, OutputPayloadError,
        OutputPayloadErrorKind,
    },
};
pub use zolana_client::audit_capsule_payload as deposit_payload;
