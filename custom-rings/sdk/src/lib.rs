//! Client library for the custom ring program: instruction builders,
//! proof-input builders, and the audited transfer flow a client runs.

pub mod instructions;
pub mod lookup_table;
pub mod prover;
pub mod shared;
pub mod transfer;

pub use custom_ring_program::{
    instructions::{
        create_config::CreateConfigIxData,
        transact::{AuditProof, CustomRingTransactIxData},
    },
    tag, CONFIG_PDA_SEED, ID as PROGRAM_ID,
};

pub use zolana_ring_client::{
    auditor_view_tag, decrypt_tx_viewing_sk, derive_audit_shared_secret, encrypt_tx_viewing_sk,
    encryption, pack32_to_2fe, pack33_to_2fe, AuditEncryptionError, AuditorEncryption,
    AuditorMessage, AUDITOR_MESSAGE_LEN, AUDIT_ENC_INFO, DOM_SEP_CR_SHARED,
};

pub use crate::{
    instructions::{
        approve_transact::{approval_pda, ApproveTransact},
        create_config::CreateConfig,
        deposit::Deposit,
        init_spp_ring_config::InitSppRingConfig,
        set_policy::{AssetRule, PolicyError, RingPolicy, SetPolicy, WithdrawalRule, SOL},
        transact::{
            to_instruction_proof, AuditProofInputError, AuditProofParams, PendingAuditProof,
            RingTransactWithAudit,
        },
    },
    lookup_table::send_v0_with_lookup_table,
    prover::CustomRingProverClient,
    shared::{config_pda, program_data_pda, ring_auth_pda},
    transfer::{ring_deposit_sol, AuditedTransfer, ProvenTransfer},
};
