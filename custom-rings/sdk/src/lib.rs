//! Instruction builders, proofs and submission for the custom ring program.
//! A blocking caller runs an operation as `zolana.block_on(op.prove(zolana.as_async()))`.

mod account;
mod admin;
mod audit;
mod deposit;
mod entry;
mod error;
mod escrow;
#[cfg(test)]
mod golden_tests;
mod key_registry;
mod merge;
mod pipeline;
mod projection;
mod prover;
mod request;
mod spend;
mod submission;
mod transact_ix;
mod trees;
mod velocity;
mod witness;

pub use custom_ring_interface::{
    compute_unit_limit, tag, CoSignScope, CustomRingProof, InstructionTag, KeyEscrow, PolicyConfig,
};
pub use zolana_program::instruction::{DepositAsset, DepositSplAccounts};

pub use crate::{
    account::{
        client_rules_match, policy_config_table, CoSignThreshold, CurrentKeyRegistryRoot,
        CustomRing, CustomRingCoSigner, CustomRingConfig, PinnedPolicy, PoolTree,
    },
    admin::{SetSpendWindow, SourceOwner},
    audit::{CustomRingProofParams, EncryptedAudit, PendingCustomRingProof},
    deposit::{Deposit, PreparedRingDeposit, RingDeposit, RingDepositReceipt},
    entry::{CreateEntry, LiveEntry, ProvenEntry, ReadEntry, UpdateEntry},
    error::RingError,
    escrow::RegistryKeyOpening,
    key_registry::{
        ProvenKeyRegistration, ReadCurrentSealedKey, ReadSealedKey, RegisterKey, SealedKeyEntry,
    },
    merge::{
        CustomRingMerge, CustomRingMergeInstruction, MergeProofInput, PreparedCustomRingMerge,
        ProvenCustomRingMerge, MAX_MERGE_INPUTS, MERGE_DEFAULT_INPUT_COUNT,
    },
    pipeline::{
        ring_authority_width, CustomRingTransfer, CustomRingTransferInput, DelegateOutput,
        DelegateTransfer, DelegateTransferInput, Delegated, Owner, ProvenDelegateTransfer,
        ProvenRingTransfer, ProvenTransfer, Rail, RailKind, RingTransfer,
    },
    prover::{to_instruction_proof, to_plain_proof},
    request::{RingIdentity, SpendRecordProofInput, VelocityProofInput},
    spend::{
        LiveSpendRecord, ProvenSpendRegistration, ReadSpendRecord, RecordOrigin, RegisterSpend,
    },
    submission::{
        RingMergeOperation, RingOperation, RingSubmission, SettledSubmission, SubmissionStatus,
    },
    transact_ix::{
        CustomRingDelegateTransact, CustomRingTransact, EscrowBinding, PolicyReads,
        PolicyTreeContext,
    },
    trees::tree_id,
    velocity::WINDOW_GUARD_SLOTS,
};
