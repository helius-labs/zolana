//! Instruction builders, proofs and submission for the custom ring program.
//! A blocking caller runs an operation as `zolana.block_on(op.prove(zolana.as_async()))`.

mod account;
mod admin;
mod deposit;
mod error;
mod heap;
mod limits;
mod merge;
mod pipeline;
mod projection;
mod prover;
mod records;
mod register_key;
mod request;
mod submission;
#[cfg(test)]
mod tests;
mod trees;

pub use custom_ring_interface::{
    compute_unit_limit, tag, CoSignScope, CustomRingProof, InstructionTag, ListRegistry, RingMode,
};
pub use zolana_program::instruction::{DepositAsset, DepositSplAccounts};

pub use crate::{
    account::{
        CoSignThreshold, CustomRing, CustomRingCoSigner, CustomRingConfig, PinnedPolicy,
        QueueStatus, RegistryRoot, RegistryStatus, RingRegistration, RingStatus,
    },
    admin::{RingSetup, SourceOwner},
    deposit::{DepositRecipient, PreparedRingDeposit, RingDeposit, RingDepositReceipt},
    error::RingError,
    merge::{
        CustomRingMerge, CustomRingMergeInstruction, MergeProofInput, PreparedCustomRingMerge,
        ProvenCustomRingMerge, RingMergeOperation, MAX_MERGE_INPUTS, MERGE_DEFAULT_INPUT_COUNT,
    },
    pipeline::{
        Anonymous, AnonymousPayment, AnonymousSpendSigner, AnonymousTransfer, CustomRingTransfer,
        CustomRingTransferInput, DelegateMove, DelegateOutput, DelegatePayment, DelegateTransfer,
        DelegateTransferInput, Delegated, Owner, PendingFirstContact, ProvenRingTransfer, Rail,
        RailKind, RingTransfer, ANCHOR_DECOYS,
    },
    records::{
        AuthorityListWrite, MemberListWrite, MemberRecords, ProvenRecordWrite, RecordApplication,
    },
    register_key::{
        EscrowedRecipients, KeyEscrowAuthority, ProvenKeyRegistration, RegisterKey, SealedEscrow,
    },
    submission::{RingOperation, RingSubmission, SettledSubmission, SubmissionStatus},
    trees::tree_id,
};
