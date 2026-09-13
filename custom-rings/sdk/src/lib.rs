//! Client library for the custom ring program: instruction builders, proof-input
//! builders, and the auditor encryption codec. Instruction data, tags, and the
//! canonical public-input hashing are defined in `custom-ring-interface` so a single
//! definition serves both sides.

mod budget;
mod delegate;
mod head_map;
mod instructions;
mod shared;
#[cfg(feature = "solana-rpc")]
mod submission;
mod transfer;
#[cfg(feature = "solana-rpc")]
mod v1;
mod velocity;
mod witness;

pub use custom_ring_interface::{
    tag, CreateConfigIxData, CustomRingProof, CustomRingTransactIxData, PolicyConfig,
    PolicyTableIxData, ReaderIxData, CONFIG_PDA_SEED, COSIGN_DEPOSITS, COSIGN_SCOPE_MASK,
    COSIGN_TRANSFERS, COSIGN_WITHDRAWALS, CO_SIGNER_PDA_SEED, CREATE_CONFIG_COMPUTE_UNIT_LIMIT,
    CREATE_HEAD_MAP_ROOT_COMPUTE_UNIT_LIMIT, CREATE_POLICY_COMPUTE_UNIT_LIMIT, DELEGATE_PDA_SEED,
    ENTRY_MUTATION_COMPUTE_UNIT_LIMIT, INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT,
    READ_ACCESS_COMPUTE_UNIT_LIMIT, READ_ACCESS_RECORD_PDA_SEED, REGISTER_SPEND_COMPUTE_UNIT_LIMIT,
    SET_AUTHORITY_COMPUTE_UNIT_LIMIT, SET_CO_SIGNER_COMPUTE_UNIT_LIMIT,
    SET_DELEGATE_COMPUTE_UNIT_LIMIT, SET_PAUSED_COMPUTE_UNIT_LIMIT,
    SET_POLICY_RULES_COMPUTE_UNIT_LIMIT, SET_POLICY_SOURCE_COMPUTE_UNIT_LIMIT,
    SET_SPEND_WINDOW_COMPUTE_UNIT_LIMIT, SPEND_WINDOW_PDA_SEED,
};

pub use zolana_interface::instruction::{DepositAsset, DepositSplAccounts};
pub use zolana_ring_client::{
    auditor_view_tag, counters_message, decrypt_counters, encrypt_counters, find_counters_message,
    AuditEncryptionError, AuditorEncryption, AuditorMessage, SpendCountersError,
    AUDITOR_MESSAGE_LEN, SPEND_COUNTERS_SLOT_INDEX,
};
pub use zolana_ring_policy::RuleTableError;

pub use crate::{
    delegate::{DelegateOutput, DelegateTransfer, DelegateTransferInput, ProvenDelegateTransfer},
    instructions::{
        cosigner::{ClearCoSigner, SetCoSigner},
        create_config::{CreateConfig, CreateConfigError},
        create_head_map_root::CreateHeadMapRoot,
        delegate::{CustomRingDelegateTransact, DelegateInstructionError, SetDelegate},
        deposit::Deposit,
        entry::{
            CreateEntry, CreatePolicy, EntryError, EntryProof, EntryProofEnvironment,
            EntryProofError, LiveEntry, ProvenEntry, ReadEntry, UpdateEntry,
        },
        grant_read_access::GrantReadAccess,
        init_spp_ring_config::InitSppRingConfig,
        merge::{
            CustomRingMerge, CustomRingMergeInstruction, CustomRingMergeProofEnvironment,
            MergeRingProver, MergeRingWitness, PreparedCustomRingMerge, ProvenCustomRingMerge,
            MAX_MERGE_INPUTS, MERGE_DEFAULT_INPUT_COUNT,
        },
        revoke_read_access::RevokeReadAccess,
        set_authority::SetAuthority,
        set_paused::SetPaused,
        set_policy_rules::SetPolicyRules,
        set_policy_source::{SetSourceOwner, SourceOwner},
        spend::{
            AsyncSpendProofEnvironment, LiveSpendRecord, ProvenSpendRegistration, ReadSpendRecord,
            RecordOrigin, RegisterSpend, SpendProofEnvironment,
        },
        spend_window::{ClearSpendWindow, SetSpendWindow},
        transact::{
            to_instruction_proof, CustomRingBaseProofRequest, CustomRingPolicyProofRequest,
            CustomRingPrivateTxHash, CustomRingProofError, CustomRingProofInputError,
            CustomRingProofParams, CustomRingTransact, EncryptedAudit, PendingCustomRingProof,
            SpendRecordWitness, VelocityWitness,
        },
    },
    shared::{
        client_rules_match, policy_config_table, AccountReadError, CustomRing, CustomRingCoSigner,
        CustomRingConfig, CustomRingDelegate, CustomRingSpendWindow, PolicyMatchError, ReaderKey,
        ReaderKeyError,
    },
    transfer::{
        tree_id, tree_id_async, AsyncTransferProofEnvironment, CustomRingTransfer,
        CustomRingTransferInput, DepositError, ProvenTransfer, RingDeposit, RingDepositReceipt,
        TransferError, TransferProofEnvironment,
    },
};

/// The compute ceiling a custom-ring transact declares. A host assembling the
/// v1 message itself must write the same value into its header, where an unset
/// field means zero rather than a default.
pub use crate::budget::TRANSACT_COMPUTE_UNIT_LIMIT;
#[cfg(feature = "solana-rpc")]
pub use crate::submission::{
    RingTransferSubmission, SubmissionEnvironment, SubmissionError, SubmissionStatus,
};
#[cfg(feature = "solana-rpc")]
pub use crate::v1::{SendError, TransactSend};
