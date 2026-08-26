//! Client library for the custom ring program: instruction builders, proof-input
//! builders, and the auditor encryption codec. Instruction data, tags, and the
//! canonical public-input hashing are defined in `custom-ring-interface` so a single
//! definition serves both sides.

mod instructions;
mod shared;
mod transfer;
mod v0;
mod witness;

pub use custom_ring_interface::{
    tag, CustomRingProof, CreateConfigIxData, CustomRingTransactIxData, PolicyConfig, ReaderIxData,
    CONFIG_PDA_SEED, CREATE_CONFIG_COMPUTE_UNIT_LIMIT, CREATE_POLICY_COMPUTE_UNIT_LIMIT,
    INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT, READ_ACCESS_COMPUTE_UNIT_LIMIT,
    READ_ACCESS_RECORD_PDA_SEED, RECORD_MUTATION_COMPUTE_UNIT_LIMIT,
    SET_AUTHORITY_COMPUTE_UNIT_LIMIT,
};

pub use zolana_ring_client::{
    auditor_view_tag, AuditEncryptionError, AuditorEncryption, AuditorMessage, AUDITOR_MESSAGE_LEN,
};

pub use crate::{
    instructions::{
        create_config::{CreateConfig, CreateConfigError},
        deposit::Deposit,
        grant_read_access::GrantReadAccess,
        init_spp_ring_config::InitSppRingConfig,
        record::{
            read_record, CreatePolicy, CreateRecord, LiveRecord, ProvenRecord, RecordError,
            RecordProof, RecordProofEnvironment, RecordProofError, UpdateRecord,
        },
        revoke_read_access::RevokeReadAccess,
        set_authority::SetAuthority,
        transact::{
            to_instruction_proof, CustomRingPrivateTxHash, CustomRingProofError, CustomRingProofInputError,
            CustomRingProofParams, CustomRingProofRequest, EncryptedAudit, PendingCustomRingProof,
            CustomRingTransact,
        },
    },
    shared::{AccountReadError, CustomRing, CustomRingConfig, ReaderKey, ReaderKeyError},
    transfer::{
        CustomRingTransfer, CustomRingTransferInput, DepositError, ProvenTransfer, RingDeposit,
        RingDepositReceipt, TransferError, TransferProofEnvironment,
    },
    v0::{SendV0Error, V0WithLookupTable, TRANSACT_COMPUTE_UNIT_LIMIT},
};
