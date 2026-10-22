//! The custom ring auditor client, free of test utilities so the end-to-end test runs its path.

mod created;
mod decrypt;
mod deposit;
mod disclosure;
mod encryption;
mod error;
mod known;
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
    created::{CreatedUtxoPage, CreatedUtxoScan, CreatedUtxos},
    decrypt::{EscrowedKeys, KnownUtxos, TransactionAudit},
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
    known::KnownUtxoIndex,
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
    records::{apply_proof_inputs, member_record, quad_path, MemberOpeningRead, RegistryTip},
    recover::{MemberRecovery, RecoveredNotes, RingRecovery, SourceMember},
    scan::{AuditedPage, RingScan, RingScanPage, ScanPage},
    types::{
        AuditedInput, AuditedInputOpening, AuditedOutput, AuditedSender, AuditedTransaction,
        AuditedUtxo, CreatedUtxo, InputOpening, InputRing, KnownUtxo, OutputOpening,
        OutputPayloadError, OutputPayloadErrorKind, UtxoOwner,
    },
};
pub use zolana_client::audit_capsule_payload as deposit_payload;
