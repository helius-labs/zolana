//! Instruction builders, proofs and submission for the custom ring program.
//! A blocking caller runs an operation as `zolana.block_on(op.prove(zolana.as_async()))`.

mod account;
mod admin;
mod audit;
mod deposit;
mod error;
#[cfg(test)]
mod golden_tests;
mod heap;
mod limits;
mod member_registry;
mod merge;
mod pipeline;
mod projection;
mod prover;
mod register_key;
mod request;
mod submission;
#[cfg(test)]
mod tests;
mod transact_ix;
mod trees;
mod witness;

pub use custom_ring_interface::{
    compute_unit_limit, tag, CoSignScope, CustomRingProof, InstructionTag, ListRegistry,
    PolicyConfig, PolicyProofKind, RingMode,
};
pub use zolana_program::instruction::{DepositAsset, DepositSplAccounts};

pub use crate::{
    account::{
        client_rules_match, policy_config_table, CoSignThreshold, CurrentRegistryRoot, CustomRing,
        CustomRingCoSigner, CustomRingConfig, PinnedPolicy, PoolTree,
    },
    admin::SourceOwner,
    audit::{CustomRingProofParams, EncryptedAudit, PendingCustomRingProof},
    deposit::{Deposit, PreparedRingDeposit, RingDeposit, RingDepositReceipt},
    error::RingError,
    member_registry::{
        MemberRecordRead, MemberWrite, ProvenMemberUpdate, ReadMemberRecord, RecordOpening,
        SealedKeyEntry, UpdateMembers,
    },
    merge::{
        CustomRingMerge, CustomRingMergeInstruction, MergeProofInput, PreparedCustomRingMerge,
        ProvenCustomRingMerge, MAX_MERGE_INPUTS, MERGE_DEFAULT_INPUT_COUNT,
    },
    pipeline::{
        ring_authority_width, Anonymous, AnonymousRecipient, AnonymousSpendSigner,
        AnonymousTransfer, CustomRingTransfer, CustomRingTransferInput, DelegateOutput,
        DelegateTransfer, DelegateTransferInput, Delegated, Owner, ProvenDelegateTransfer,
        ProvenRingTransfer, ProvenTransfer, Rail, RailKind, RingTransfer,
    },
    prover::{to_instruction_proof, to_plain_proof},
    register_key::{ProvenKeyRegistration, RegisterKey},
    request::{OutflowLimitProofInput, RingIdentity},
    submission::{
        RingMergeOperation, RingOperation, RingSubmission, SettledSubmission, SubmissionStatus,
    },
    transact_ix::{
        CustomRingDelegateTransact, CustomRingTransact, EscrowBinding, ForeignBinding, PolicyReads,
        PolicyTreeContext, RegistryBinding,
    },
    trees::tree_id,
};
