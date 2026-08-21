//! Client library for the custom ring program: instruction builders, proof-input
//! builders, and the auditor encryption codec. Instruction data, tags, and the
//! canonical public-input hashing are defined in `zolana-interface` so a single
//! definition serves both sides.

mod instructions;
mod shared;
mod transfer;

pub use zolana_interface::custom_ring::{
    tag, AuditProof, CreateConfigIxData, CustomRingTransactIxData, ReaderIxData, CONFIG_PDA_SEED,
    READER_RECORD_PDA_SEED,
};

pub use zolana_ring_client::{
    auditor_view_tag, AuditEncryptionError, AuditorEncryption, AuditorMessage, AUDITOR_MESSAGE_LEN,
};

pub use crate::{
    instructions::{
        create_config::{CreateConfig, CreateConfigError},
        deposit::Deposit,
        grant_reader::GrantReader,
        init_spp_ring_config::InitSppRingConfig,
        revoke_reader::RevokeReader,
        transact::{
            to_instruction_proof, AuditProofError, AuditProofInputError, AuditProofParams,
            EncryptedAudit, PendingAuditProof, RingTransactWithAudit,
        },
    },
    shared::{AccountReadError, CustomRing, CustomRingConfig, ReaderKey, ReaderKeyError},
    transfer::{
        AuditedTransfer, AuditedTransferInput, DepositError, ProvenTransfer, RingDeposit,
        RingDepositReceipt, TransferError, TransferProofEnvironment,
    },
};
